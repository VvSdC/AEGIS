"""
AEGIS Guardrail Engine
Two-tier filtering system.

Tier 1 (<30ms): PII patterns (and optional legacy jailbreak/injection regex)
Tier 2 (async): Llama Guard 3 on Hugging Face for semantic input safety
Output Tier 2: Regional compliance assessment via configured chat model (optional)
"""

import re
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import asyncio

# YARA integration - graceful fallback if not installed
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: yara-python not installed. YARA rules will be disabled.")

from ..config import settings
from .inference_providers import get_inference_router
from .llama_guard import (
    categories_to_block_reason,
    classify_user_prompt,
    is_llama_guard_available,
)


@dataclass
class FilterMatch:
    """Represents a single filter match."""
    filter_name: str
    category: str  # pii, jailbreak, injection, insecure_code, bias, compliance
    matched_text: str
    start: int
    end: int
    replacement: Optional[str] = None
    confidence: float = 1.0
    tier: int = 1


@dataclass
class FilterResult:
    """Result of running filters on text."""
    original_text: str
    filtered_text: str
    blocked: bool = False
    block_reason: Optional[str] = None
    matches: List[FilterMatch] = field(default_factory=list)
    tier1_latency_ms: float = 0.0
    tier2_latency_ms: Optional[float] = None
    total_latency_ms: float = 0.0


class GuardrailEngine:
    """
    Two-tier guardrail filtering engine.
    
    Tier 1: Fast PII pattern matching (<30ms)
    Tier 2: Llama Guard 3 on Hugging Face (semantic, multilingual)
    
    PII Detection:
    - Hard Block: Exact patterns (PAN, Aadhaar, SSN, Credit Card, non-local IP) → Immediate rejection
    - Soft Block: Ambiguous patterns (phone, email) → Warning + allow with redaction
    """
    
    # PII patterns are loaded from patterns/pii_patterns.json (region-keyed).
    # See _load_pii_patterns_from_json().

    # Jailbreak and injection patterns loaded from patterns/prompt_patterns.json.
    # See _load_prompt_patterns_from_json().

    def __init__(self):
        """Initialize the guardrail engine."""
        self._pii_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self._compiled_jailbreak_patterns: List[Tuple[re.Pattern, str]] = []
        self._compiled_injection_patterns: List[Tuple[re.Pattern, str]] = []
        self._compiled_code_patterns: Dict[str, List[Dict[str, Any]]] = {}  # category -> patterns
        self._yara_rules: Optional[Any] = None
        self._llama_guard_ready = False
        self._compliance_provider: Optional[str] = None
        self._compliance_model: Optional[str] = None
        
        self._load_prompt_patterns_from_json()
        self._load_pii_patterns_from_json()
        self._load_code_patterns_from_json()
        self._load_yara_rules()
        self._init_guard_backends()
    
    def _load_prompt_patterns_from_json(self):
        """Load jailbreak and injection patterns from patterns/prompt_patterns.json."""
        import json
        FLAG_MAP = {
            "IGNORECASE": re.IGNORECASE,
            "MULTILINE": re.MULTILINE,
            "DOTALL": re.DOTALL,
        }
        patterns_file = Path(__file__).parent.parent / "patterns" / "prompt_patterns.json"
        if not patterns_file.exists():
            print(f"Prompt patterns file not found: {patterns_file}")
            return
        try:
            data = json.loads(patterns_file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Failed to parse prompt patterns JSON: {e}")
            return

        for entity in data.get("jailbreak", {}).get("entities", []):
            for pat in entity.get("patterns", []):
                flags = 0
                for fname in pat.get("flags", []):
                    flags |= FLAG_MAP.get(str(fname).upper(), 0)
                try:
                    self._compiled_jailbreak_patterns.append(
                        (re.compile(pat["regex"], flags), entity["name"])
                    )
                except re.error as e:
                    print(f"Bad regex in jailbreak/{entity['name']}: {e}")

        for entity in data.get("injection", {}).get("entities", []):
            for pat in entity.get("patterns", []):
                flags = 0
                for fname in pat.get("flags", []):
                    flags |= FLAG_MAP.get(str(fname).upper(), 0)
                try:
                    self._compiled_injection_patterns.append(
                        (re.compile(pat["regex"], flags), entity["name"])
                    )
                except re.error as e:
                    print(f"Bad regex in injection/{entity['name']}: {e}")

        print(f"Loaded {len(self._compiled_jailbreak_patterns)} jailbreak, {len(self._compiled_injection_patterns)} injection patterns")

    def _load_code_patterns_from_json(self):
        """Load insecure code patterns from patterns/code_patterns.json for SAST-like detection."""
        import json
        FLAG_MAP = {
            "IGNORECASE": re.IGNORECASE,
            "MULTILINE": re.MULTILINE,
            "DOTALL": re.DOTALL,
        }
        patterns_file = Path(__file__).parent.parent / "patterns" / "code_patterns.json"
        if not patterns_file.exists():
            print(f"Code patterns file not found: {patterns_file}")
            return
        try:
            data = json.loads(patterns_file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Failed to parse code patterns JSON: {e}")
            return

        total_patterns = 0
        for category_name, category_data in data.get("categories", {}).items():
            category_patterns = []
            for entity in category_data.get("entities", []):
                compiled_patterns = []
                for pat in entity.get("patterns", []):
                    flags = 0
                    for fname in pat.get("flags", []):
                        flags |= FLAG_MAP.get(str(fname).upper(), 0)
                    try:
                        compiled_patterns.append({
                            "regex": re.compile(pat["regex"], flags),
                            "description": pat.get("description", ""),
                        })
                        total_patterns += 1
                    except re.error as e:
                        print(f"Bad regex in code_patterns/{category_name}/{entity['name']}: {e}")
                if compiled_patterns:
                    category_patterns.append({
                        "name": entity["name"],
                        "description": entity.get("description", ""),
                        "severity": entity.get("severity", "medium"),
                        "cwe": entity.get("cwe", ""),
                        "languages": entity.get("languages", ["all"]),
                        "patterns": compiled_patterns,
                    })
            if category_patterns:
                self._compiled_code_patterns[category_name] = category_patterns

        print(f"Loaded {total_patterns} insecure code patterns across {len(self._compiled_code_patterns)} categories")

    def _load_pii_patterns_from_json(self):
        """Load PII/credential patterns from patterns/pii_patterns.json.
        Supports both 'regions' (region-specific PII) and 'categories' (credentials, applied as GLOBAL).
        """
        import json
        FLAG_MAP = {
            "IGNORECASE": re.IGNORECASE,
            "MULTILINE": re.MULTILINE,
            "DOTALL": re.DOTALL,
        }
        patterns_file = Path(__file__).parent.parent / "patterns" / "pii_patterns.json"
        if not patterns_file.exists():
            print(f"PII patterns file not found: {patterns_file}")
            return
        try:
            data = json.loads(patterns_file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Failed to parse PII patterns JSON: {e}")
            return

        def _compile_entities(entity_list, label=""):
            entities = []
            for entity in entity_list:
                compiled = []
                for pat in entity.get("patterns", []):
                    flags = 0
                    for fname in pat.get("flags", []):
                        flags |= FLAG_MAP.get(str(fname).upper(), 0)
                    try:
                        compiled.append(re.compile(pat["regex"], flags))
                    except re.error as e:
                        print(f"Bad regex in {label}/{entity.get('name')}: {e}")
                entities.append({
                    "name": entity["name"],
                    "block_type": entity.get("block_type", "soft"),
                    "replacement": entity.get("replacement", "[REDACTED]"),
                    "block_reason": entity.get("block_reason", entity.get("description", "PII detected")),
                    "patterns": compiled,
                })
            return entities

        for region, region_data in data.get("regions", {}).items():
            self._pii_by_region[region.upper()] = _compile_entities(
                region_data.get("entities", []), label=region
            )

        for cat_name, cat_data in data.get("categories", {}).items():
            global_entities = _compile_entities(
                cat_data.get("entities", []), label=cat_name
            )
            self._pii_by_region.setdefault("GLOBAL", []).extend(global_entities)

        total = sum(len(v) for v in self._pii_by_region.values())
        print(f"Loaded {total} PII entities across {len(self._pii_by_region)} region(s)")

    _REGION_ALIASES = {
        "IN": "INDIA", "INDIA": "INDIA",
        "US": "USA", "USA": "USA", "US-HEALTHCARE": "USA", "US-FINANCIAL": "USA",
        "UK": "UK", "GB": "UK", "GBR": "UK",
        "AU": "AUSTRALIA", "AUSTRALIA": "AUSTRALIA",
        "RU": "RUSSIA", "RUSSIA": "RUSSIA",
        "EU": "EUROPE", "EUROPE": "EUROPE",
        "GLOBAL": "GLOBAL",
    }

    def _get_entities_for_region(self, region):
        """Return region-specific entities first (so they short-circuit first), then GLOBAL."""
        key = self._REGION_ALIASES.get((region or "").upper(), (region or "").upper())
        entities = []
        if key and key != "GLOBAL" and key in self._pii_by_region:
            entities.extend(self._pii_by_region[key])
        entities.extend(self._pii_by_region.get("GLOBAL", []))
        return entities

    def _load_yara_rules(self):
        """Load YARA rules from files."""
        if not YARA_AVAILABLE:
            return
        
        rules_dir = Path(__file__).parent.parent / "yara_rules"
        if not rules_dir.exists():
            print(f"YARA rules directory not found: {rules_dir}")
            return
        
        rule_files = {}
        for rule_file in rules_dir.glob("*.yar"):
            rule_files[rule_file.stem] = str(rule_file)
        
        if rule_files:
            try:
                self._yara_rules = yara.compile(filepaths=rule_files)
                print(f"Loaded {len(rule_files)} YARA rule files")
            except Exception as e:
                print(f"Error loading YARA rules: {e}")
    
    def _init_guard_backends(self):
        """Llama Guard (HF) for input Tier 2; chat model for output compliance Tier 2."""
        self._llama_guard_ready = is_llama_guard_available()
        if self._llama_guard_ready:
            print(f"✅ Guardrails: Tier 2 input → Llama Guard ({settings.llama_guard_model}) via Hugging Face")
        elif settings.tier2_enabled:
            print("⚠️ Guardrails: Tier 2 input disabled (set HUGGINGFACE_API_KEY and accept Llama Guard license on HF)")

        router = get_inference_router()
        for provider_name in ("gemini", "mistral", "openrouter"):
            options = router.get_models_for_provider(provider_name)
            provider_options = router.get_available_provider_options()
            provider_state = next((o for o in provider_options if o["provider"] == provider_name), None)
            if provider_state and provider_state.get("available") and options:
                self._compliance_provider = provider_name
                self._compliance_model = options[0]
                print(f"✅ Guardrails: Output compliance Tier 2 → {provider_name}")
                return
        self._compliance_provider = None
        self._compliance_model = None
        print("⚠️ Guardrails: Output compliance Tier 2 unavailable (no chat provider configured)")
    
    def _run_pii_filter(self, text, region=None):
        """
        Region-aware PII filter.

        Pass 1: hard-block patterns. First match short-circuits (no further scanning).
        Pass 2: soft-block patterns. All occurrences redacted.
        """
        matches = []
        filtered = text
        entities = self._get_entities_for_region(region)

        for entity in entities:
            if entity["block_type"] != "hard":
                continue
            for pattern in entity["patterns"]:
                hit = pattern.search(text)
                if hit:
                    matches.append(FilterMatch(
                        filter_name="pii_" + entity["name"].lower() + "_HARD",
                        category="pii_hard_block",
                        matched_text=hit.group(),
                        start=hit.start(), end=hit.end(),
                        replacement=entity["replacement"],
                        confidence=0.99,
                        tier=1,
                    ))
                    reason = "Hard Block: " + entity["block_reason"] + " - " + repr(hit.group())
                    return text, matches, True, reason

        for entity in entities:
            if entity["block_type"] != "soft":
                continue
            for pattern in entity["patterns"]:
                for hit in pattern.finditer(filtered):
                    matches.append(FilterMatch(
                        filter_name="pii_" + entity["name"].lower() + "_SOFT",
                        category="pii_soft_block",
                        matched_text=hit.group(),
                        start=hit.start(), end=hit.end(),
                        replacement=entity["replacement"],
                        confidence=0.7,
                        tier=1,
                    ))
                filtered = pattern.sub(entity["replacement"], filtered)

        return filtered, matches, False, None
    
    def _run_jailbreak_filter(self, text: str) -> Tuple[bool, List[FilterMatch]]:
        """
        Tier 1: Detect jailbreak attempts using regex + YARA.
        Returns (should_block, matches).
        """
        matches = []
        should_block = False
        
        # Regex-based detection
        for pattern, name in self._compiled_jailbreak_patterns:
            for match in pattern.finditer(text):
                matches.append(FilterMatch(
                    filter_name=name,
                    category="jailbreak",
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.9,
                    tier=1
                ))
                should_block = True
        
        # YARA-based detection
        if self._yara_rules:
            yara_matches = self._yara_rules.match(data=text.encode())
            for ym in yara_matches:
                if ym.rule.startswith("jailbreak"):
                    matches.append(FilterMatch(
                        filter_name=f"yara_{ym.rule}",
                        category="jailbreak",
                        matched_text=str(ym.strings) if ym.strings else "",
                        start=0,
                        end=0,
                        confidence=0.95,
                        tier=1
                    ))
                    should_block = True
        
        return should_block, matches
    
    def _run_injection_filter(self, text: str) -> Tuple[bool, List[FilterMatch]]:
        """
        Tier 1: Detect prompt injection attempts.
        Returns (should_block, matches).
        """
        matches = []
        should_block = False
        
        # Regex-based detection
        for pattern, name in self._compiled_injection_patterns:
            for match in pattern.finditer(text):
                matches.append(FilterMatch(
                    filter_name=name,
                    category="injection",
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.85,
                    tier=1
                ))
                should_block = True
        
        # YARA-based detection
        if self._yara_rules:
            yara_matches = self._yara_rules.match(data=text.encode())
            for ym in yara_matches:
                if ym.rule.startswith("injection"):
                    matches.append(FilterMatch(
                        filter_name=f"yara_{ym.rule}",
                        category="injection",
                        matched_text=str(ym.strings) if ym.strings else "",
                        start=0,
                        end=0,
                        confidence=0.95,
                        tier=1
                    ))
                    should_block = True
        
        return should_block, matches
    
    def _run_insecure_code_filter(self, text: str) -> Tuple[bool, List[FilterMatch]]:
        """
        Tier 1: Detect insecure code patterns in LLM-generated code.
        Uses patterns from SAST tools (Bandit, Bearer, Semgrep, etc.).
        Returns (has_findings, matches) - does not block by default, just flags.
        """
        matches = []
        has_critical = False
        
        # Severity to confidence mapping
        severity_confidence = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
        }
        
        for category_name, entities in self._compiled_code_patterns.items():
            for entity in entities:
                entity_severity = entity.get("severity", "medium")
                entity_cwe = entity.get("cwe", "")
                confidence = severity_confidence.get(entity_severity, 0.70)
                
                for pat_info in entity.get("patterns", []):
                    pattern = pat_info["regex"]
                    for match in pattern.finditer(text):
                        matches.append(FilterMatch(
                            filter_name=f"code_{entity['name']}",
                            category=f"insecure_code_{category_name}",
                            matched_text=match.group()[:200],  # Truncate long matches
                            start=match.start(),
                            end=match.end(),
                            confidence=confidence,
                            tier=1,
                            replacement=f"[{entity_severity.upper()}:{entity_cwe}] {pat_info.get('description', entity['description'])}",
                        ))
                        if entity_severity == "critical":
                            has_critical = True
        
        return has_critical, matches
    
    def run_tier1(self, text: str, direction: str = "prompt", region: Optional[str] = None) -> FilterResult:
        """
        Run Tier 1 filters: fast regex + YARA pattern matching.
        Target: <30ms latency.
        """
        start_time = time.perf_counter()
        all_matches = []
        filtered_text = text
        blocked = False
        block_reason = None
        
        # 1. PII Detection & Redaction (with hard/soft block distinction)
        filtered_text, pii_matches, pii_blocked, pii_block_reason = self._run_pii_filter(filtered_text, region=region)
        all_matches.extend(pii_matches)
        if pii_blocked:
            blocked = True
            block_reason = pii_block_reason
        
        if settings.tier1_jailbreak_injection_patterns:
            jailbreak_blocked, jailbreak_matches = self._run_jailbreak_filter(text)
            all_matches.extend(jailbreak_matches)
            if jailbreak_blocked and not blocked:
                blocked = True
                block_reason = "Jailbreak attempt detected"

            injection_blocked, injection_matches = self._run_injection_filter(text)
            all_matches.extend(injection_matches)
            if injection_blocked and not blocked:
                blocked = True
                block_reason = "Prompt injection detected"

        # 2. Insecure Code Detection on prompts (flags only; output scan is primary)
        code_critical, code_matches = self._run_insecure_code_filter(text)
        all_matches.extend(code_matches)
        if code_critical and not blocked:
            # For response direction, we may want to warn but not block
            # For now, critical code issues are flagged but not auto-blocked
            pass  # Uncomment below to enable blocking on critical code issues
            # blocked = True
            # block_reason = "Critical insecure code pattern detected"
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return FilterResult(
            original_text=text,
            filtered_text=filtered_text if not blocked else "[BLOCKED]",
            blocked=blocked,
            block_reason=block_reason,
            matches=all_matches,
            tier1_latency_ms=elapsed_ms,
            total_latency_ms=elapsed_ms
        )
    
    async def run_tier2(self, text: str, tier1_result: FilterResult) -> FilterResult:
        """
        Run Tier 2 input safety via Llama Guard 3 (Hugging Face).
        """
        if not self._llama_guard_ready:
            return tier1_result

        guard = await classify_user_prompt(text)
        tier1_result.tier2_latency_ms = guard.latency_ms
        tier1_result.total_latency_ms = tier1_result.tier1_latency_ms + guard.latency_ms

        if guard.error:
            print(f"Llama Guard warning (fail-open): {guard.error}")
            return tier1_result

        if not guard.safe and not tier1_result.blocked:
            reason = categories_to_block_reason(guard.categories)
            tier1_result.blocked = True
            tier1_result.block_reason = reason
            tier1_result.matches.append(
                FilterMatch(
                    filter_name="llama_guard_3",
                    category="safety",
                    matched_text=guard.raw_response[:200],
                    start=0,
                    end=0,
                    confidence=0.92,
                    tier=2,
                )
            )
            for cat in guard.categories:
                tier1_result.matches.append(
                    FilterMatch(
                        filter_name=f"llama_guard_{cat}",
                        category="safety",
                        matched_text=cat,
                        start=0,
                        end=0,
                        confidence=0.9,
                        tier=2,
                    )
                )

        return tier1_result
    
    async def filter(
        self,
        text: str,
        direction: str = "prompt",
        tier: str = "both",
        filters: Optional[List[str]] = None,
        region: Optional[str] = None,
    ) -> FilterResult:
        """
        Main entry point: run guardrail filters on text.
        
        Args:
            text: Text to filter
            direction: "prompt" or "response"
            tier: "1", "2", or "both"
            filters: Specific filters to apply (None = all)
        
        Returns:
            FilterResult with filtered text and match details
        """
        # Run Tier 1
        result = self.run_tier1(text, direction, region=region)
        
        # Run Tier 2 if enabled and not blocked by Tier 1
        if tier in ("2", "both") and not result.blocked:
            result = await self.run_tier2(text, result)
        
        return result

    # =========================================================================
    # OUTPUT GUARDRAILS (Warn-only, no blocking)
    # =========================================================================
    
    def run_output_tier1(self, response_text: str, region: Optional[str] = None) -> Dict[str, Any]:
        """
        Output Tier 1: Pattern-based warning scan.
        Does NOT block or redact - just identifies potential issues for user awareness.
        
        Returns dict with:
            - findings: list of issues found
            - has_warnings: bool
            - warning_summary: human-readable summary
            - latency_ms: processing time
        """
        start_time = time.perf_counter()
        findings = []
        
        # 1. PII Detection (warn, don't redact)
        _, pii_matches, _, _ = self._run_pii_filter(response_text, region=region)
        for m in pii_matches:
            severity = "critical" if "HARD" in m.filter_name else "warning"
            findings.append({
                "category": "pii",
                "severity": severity,
                "description": f"Potential PII detected: {m.filter_name.replace('pii_', '').replace('_HARD', '').replace('_SOFT', '')}",
                "matched_text": m.matched_text[:50] + "..." if len(m.matched_text) > 50 else m.matched_text,
                "confidence": m.confidence,
            })
        
        # 2. Insecure Code Detection (warn)
        _, code_matches = self._run_insecure_code_filter(response_text)
        for m in code_matches:
            severity = "critical" if m.confidence >= 0.9 else "warning"
            findings.append({
                "category": "insecure_code",
                "severity": severity,
                "description": m.replacement or f"Insecure code pattern: {m.filter_name}",
                "matched_text": m.matched_text[:100] + "..." if len(m.matched_text) > 100 else m.matched_text,
                "confidence": m.confidence,
            })
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        has_warnings = len(findings) > 0
        warning_summary = None
        if has_warnings:
            categories = list(set(f["category"] for f in findings))
            critical_count = sum(1 for f in findings if f["severity"] == "critical")
            warning_count = sum(1 for f in findings if f["severity"] == "warning")
            
            parts = []
            if critical_count > 0:
                parts.append(f"{critical_count} critical")
            if warning_count > 0:
                parts.append(f"{warning_count} warning(s)")
            
            warning_summary = f"Found {', '.join(parts)} in categories: {', '.join(categories)}. Review recommended before use."
        
        return {
            "findings": findings,
            "has_warnings": has_warnings,
            "warning_summary": warning_summary,
            "latency_ms": elapsed_ms,
        }
    
    async def run_output_tier2(
        self, 
        original_prompt: str,
        response_text: str, 
        region: str,
        tier1_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Output Tier 2: LLM-based compliance and safety assessment.
        Checks if response complies with region-based regulations.
        Does NOT block - provides assessment and recommendations.
        
        Returns dict with:
            - compliant: bool
            - safety_score: 0.0-1.0
            - compliance_findings: list of compliance issues
            - policies_checked: list of regulation names
            - assessment: human-readable assessment
            - recommendations: list of recommendations
            - latency_ms: processing time
        """
        start_time = time.perf_counter()
        
        if not self._compliance_provider or not self._compliance_model:
            return {
                "compliant": True,
                "safety_score": 1.0,
                "compliance_findings": [],
                "region": region,
                "policies_checked": [],
                "assessment": "Output compliance Tier 2 unavailable (no chat provider configured).",
                "recommendations": [],
                "latency_ms": 0.0,
            }
        
        # Import region policies
        from .region_policies import REGION_POLICIES, get_policies_for_region
        
        policy_info = REGION_POLICIES.get(region.lower(), REGION_POLICIES.get("india", {}))
        policies = get_policies_for_region(region.lower())
        
        # Build Tier 1 context
        tier1_context = ""
        if tier1_findings:
            tier1_context = f"\n\nTier 1 findings (already detected):\n"
            for f in tier1_findings[:5]:  # Limit to first 5
                tier1_context += f"- [{f['severity'].upper()}] {f['category']}: {f['description']}\n"
        
        assessment_prompt = f"""You are a regulatory compliance assessor for AI systems.

TASK: Assess whether the AI response below complies with the regulations for region "{region.upper()}".

APPLICABLE REGULATIONS:
{chr(10).join(f'- {act}' for act in policies)}

COMPLIANCE REQUIREMENTS:
{policy_info.get('summary', 'Ensure response is safe, accurate, and respects privacy.')}
{tier1_context}

ORIGINAL USER PROMPT:
\"\"\"{original_prompt[:500]}\"\"\"

AI RESPONSE TO ASSESS:
\"\"\"{response_text[:2000]}\"\"\"

Provide your assessment in this JSON format:
{{
    "compliant": true/false,
    "safety_score": 0.0-1.0,
    "findings": [
        {{
            "category": "privacy|bias|accuracy|safety|compliance",
            "severity": "info|warning|critical",
            "regulation": "exact regulation name from list above",
            "description": "specific issue found"
        }}
    ],
    "assessment": "2-3 sentence overall assessment",
    "recommendations": ["actionable recommendation 1", "recommendation 2"]
}}

If the response is safe and compliant, return compliant=true, safety_score close to 1.0, empty findings, and a brief positive assessment.
"""
        
        try:
            router = get_inference_router()
            result_text = await router.generate(
                self._compliance_provider, self._compliance_model, assessment_prompt
            )
            
            import json
            json_start = result_text.find('{')
            json_end = result_text.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                result = json.loads(result_text[json_start:json_end])
                
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                
                return {
                    "compliant": result.get("compliant", True),
                    "safety_score": result.get("safety_score", 1.0),
                    "compliance_findings": [
                        {
                            "category": f.get("category", "compliance"),
                            "severity": f.get("severity", "info"),
                            "description": f"{f.get('regulation', 'Regulation')}: {f.get('description', '')}",
                            "matched_text": None,
                            "confidence": 0.85,
                        }
                        for f in result.get("findings", [])
                    ],
                    "region": region,
                    "policies_checked": policies,
                    "assessment": result.get("assessment", "Assessment completed."),
                    "recommendations": result.get("recommendations", []),
                    "latency_ms": elapsed_ms,
                }
        except Exception as e:
            print(f"Output Tier 2 assessment error: {e}")
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return {
            "compliant": True,
            "safety_score": 0.8,
            "compliance_findings": [],
            "region": region,
            "policies_checked": policies,
            "assessment": "Assessment could not be completed due to an error. Manual review recommended.",
            "recommendations": ["Review response manually for compliance"],
            "latency_ms": elapsed_ms,
        }
    
    async def assess_output(
        self,
        original_prompt: str,
        response_text: str,
        region: str = "india",
        tier: str = "tier1",
    ) -> Dict[str, Any]:
        """
        Main entry point for output guardrails.
        
        Args:
            original_prompt: The user's original prompt
            response_text: The model's response to assess
            region: Region for compliance checking
            tier: "tier1" (pattern warnings) or "tier2" (compliance assessment)
        
        Returns:
            Dict with tier1, tier2 results, safe_to_use flag, and summary
        """
        result = {
            "tier1": None,
            "tier2": None,
            "safe_to_use": True,
            "action_required": False,
            "summary": "Output passed all checks.",
        }
        
        # Always run Tier 1 for basic checks
        tier1_result = self.run_output_tier1(response_text, region=region)
        result["tier1"] = tier1_result
        
        # Run Tier 2 if requested
        if tier == "tier2":
            tier2_result = await self.run_output_tier2(
                original_prompt=original_prompt,
                response_text=response_text,
                region=region,
                tier1_findings=tier1_result["findings"],
            )
            result["tier2"] = tier2_result
            
            # Determine overall status based on Tier 2
            if not tier2_result["compliant"] or tier2_result["safety_score"] < 0.7:
                result["safe_to_use"] = False
                result["action_required"] = True
                result["summary"] = tier2_result["assessment"]
            elif tier2_result["safety_score"] < 0.9 or tier1_result["has_warnings"]:
                result["action_required"] = True
                result["summary"] = f"Review recommended: {tier2_result['assessment']}"
            else:
                result["summary"] = tier2_result["assessment"]
        else:
            # Tier 1 only - base assessment on warnings
            if tier1_result["has_warnings"]:
                critical_count = sum(1 for f in tier1_result["findings"] if f["severity"] == "critical")
                if critical_count > 0:
                    result["action_required"] = True
                    result["summary"] = tier1_result["warning_summary"]
                else:
                    result["summary"] = tier1_result["warning_summary"] or "Minor warnings detected. Review recommended."
            else:
                result["summary"] = "No issues detected in output."
        
        return result


# Singleton instance
_guardrail_engine: Optional[GuardrailEngine] = None


def get_guardrail_engine() -> GuardrailEngine:
    """Get or create the guardrail engine singleton."""
    global _guardrail_engine
    if _guardrail_engine is None:
        _guardrail_engine = GuardrailEngine()
    return _guardrail_engine
