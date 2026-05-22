"""
AEGIS Policy Engine
Region-aware policy enforcement with configurable rule packs.

Supports:
- Loading policy packs from JSON files
- Region-based policy routing (EU, US, APAC, Global)
- Rule evaluation against system metadata
- Compliance reporting with pass/fail/warning
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PolicyRule:
    """A single policy rule."""
    id: str
    name: str
    description: str
    category: str  # transparency, fairness, accountability, privacy, security
    severity: Severity
    check_type: str  # boolean, threshold, regex, list_contains, custom
    check_config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity.value,
            "check_type": self.check_type,
            "check_config": self.check_config,
        }


@dataclass
class PolicyPack:
    """A collection of related policy rules."""
    name: str
    region: str
    category: str
    version: str
    description: str
    rules: List[PolicyRule]
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "region": self.region,
            "category": self.category,
            "version": self.version,
            "description": self.description,
            "rules": [r.to_dict() for r in self.rules],
            "enabled": self.enabled,
        }


@dataclass
class EvaluationResult:
    """Result of evaluating a single rule."""
    rule_id: str
    rule_name: str
    passed: bool
    severity: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyEvaluation:
    """Full policy evaluation result."""
    system_name: str
    region: str
    policies_evaluated: List[str]
    passed_rules: List[EvaluationResult]
    failed_rules: List[EvaluationResult]
    warnings: List[str]
    overall_compliant: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_name": self.system_name,
            "region": self.region,
            "policies_evaluated": self.policies_evaluated,
            "passed_rules": [{"rule_id": r.rule_id, "rule_name": r.rule_name, "message": r.message} for r in self.passed_rules],
            "failed_rules": [{"rule_id": r.rule_id, "rule_name": r.rule_name, "severity": r.severity, "message": r.message} for r in self.failed_rules],
            "warnings": self.warnings,
            "overall_compliant": self.overall_compliant,
        }


class PolicyEngine:
    """
    Policy evaluation engine with region-based routing.
    
    Policies are loaded from JSON files in the policies/ directory.
    Region routing automatically selects applicable policy packs.
    """
    
    # Region to policy mapping
    REGION_POLICIES = {
        "EU": ["eu_ai_act", "gdpr_ai"],
        "US": ["nist_ai_rmf", "ccpa_ai"],
        "US-HEALTHCARE": ["nist_ai_rmf", "hipaa_ai"],
        "US-FINANCIAL": ["nist_ai_rmf", "sox_ai_controls"],
        "APAC": ["singapore_feat"],
        "CANADA": ["canada_aida"],
        "GLOBAL": ["internal_baseline", "iso_42001"],
    }
    
    def __init__(self):
        """Initialize the policy engine."""
        self._policy_packs: Dict[str, PolicyPack] = {}
        self._load_builtin_policies()
    
    def _load_builtin_policies(self):
        """Load built-in policy templates."""
        policies_dir = Path(__file__).parent.parent / "policies"
        
        if policies_dir.exists():
            for policy_file in policies_dir.glob("*.json"):
                try:
                    with open(policy_file, "r") as f:
                        data = json.load(f)
                        policy = self._parse_policy(data)
                        self._policy_packs[policy.name.lower().replace(" ", "_")] = policy
                except Exception as e:
                    print(f"Error loading policy {policy_file}: {e}")
        
        # If no files found, load default policies
        if not self._policy_packs:
            self._load_default_policies()
    
    def _load_default_policies(self):
        """Load hardcoded default policies."""
        # Internal Baseline
        self._policy_packs["internal_baseline"] = PolicyPack(
            name="Internal Baseline",
            region="GLOBAL",
            category="general",
            version="1.0.0",
            description="Organization-wide minimum AI governance standards",
            rules=[
                PolicyRule(
                    id="baseline_001",
                    name="Audit Logging Required",
                    description="All AI system interactions must be logged",
                    category="accountability",
                    severity=Severity.HIGH,
                    check_type="boolean",
                    check_config={"field": "audit_logging_enabled", "expected": True}
                ),
                PolicyRule(
                    id="baseline_002",
                    name="PII Filtering Required",
                    description="Systems handling PII must have filtering enabled",
                    category="privacy",
                    severity=Severity.CRITICAL,
                    check_type="conditional",
                    check_config={
                        "condition_field": "handles_pii",
                        "check_field": "pii_filtering_enabled",
                        "expected": True
                    }
                ),
                PolicyRule(
                    id="baseline_003",
                    name="Human Oversight for High-Risk",
                    description="High-risk systems require human oversight",
                    category="accountability",
                    severity=Severity.HIGH,
                    check_type="conditional",
                    check_config={
                        "condition_field": "risk_level",
                        "condition_value": ["HIGH", "CRITICAL"],
                        "check_field": "human_oversight",
                        "expected": True
                    }
                ),
                PolicyRule(
                    id="baseline_004",
                    name="Model Documentation",
                    description="AI models must have documented capabilities and limitations",
                    category="transparency",
                    severity=Severity.MEDIUM,
                    check_type="boolean",
                    check_config={"field": "model_documented", "expected": True}
                ),
                PolicyRule(
                    id="baseline_005",
                    name="Bias Testing",
                    description="Systems must undergo bias testing before deployment",
                    category="fairness",
                    severity=Severity.HIGH,
                    check_type="boolean",
                    check_config={"field": "bias_tested", "expected": True}
                ),
            ]
        )
        
        # EU AI Act
        self._policy_packs["eu_ai_act"] = PolicyPack(
            name="EU AI Act",
            region="EU",
            category="regulatory",
            version="1.0.0",
            description="European Union AI Act compliance requirements",
            rules=[
                PolicyRule(
                    id="euai_001",
                    name="Risk Classification",
                    description="AI system must have a documented risk classification",
                    category="accountability",
                    severity=Severity.CRITICAL,
                    check_type="boolean",
                    check_config={"field": "risk_classified", "expected": True}
                ),
                PolicyRule(
                    id="euai_002",
                    name="High-Risk Human Oversight",
                    description="High-risk AI requires effective human oversight",
                    category="accountability",
                    severity=Severity.CRITICAL,
                    check_type="conditional",
                    check_config={
                        "condition_field": "risk_level",
                        "condition_value": ["HIGH", "CRITICAL"],
                        "check_field": "human_oversight",
                        "expected": True
                    }
                ),
                PolicyRule(
                    id="euai_003",
                    name="Transparency Obligation",
                    description="Users must be informed they are interacting with AI",
                    category="transparency",
                    severity=Severity.HIGH,
                    check_type="boolean",
                    check_config={"field": "ai_disclosure", "expected": True}
                ),
                PolicyRule(
                    id="euai_004",
                    name="Technical Documentation",
                    description="High-risk systems require comprehensive technical documentation",
                    category="transparency",
                    severity=Severity.HIGH,
                    check_type="conditional",
                    check_config={
                        "condition_field": "risk_level",
                        "condition_value": ["HIGH", "CRITICAL"],
                        "check_field": "technical_docs",
                        "expected": True
                    }
                ),
                PolicyRule(
                    id="euai_005",
                    name="Conformity Assessment",
                    description="High-risk systems must pass conformity assessment",
                    category="accountability",
                    severity=Severity.CRITICAL,
                    check_type="conditional",
                    check_config={
                        "condition_field": "risk_level",
                        "condition_value": ["HIGH", "CRITICAL"],
                        "check_field": "conformity_assessed",
                        "expected": True
                    }
                ),
            ]
        )
        
        # GDPR AI
        self._policy_packs["gdpr_ai"] = PolicyPack(
            name="GDPR AI",
            region="EU",
            category="privacy",
            version="1.0.0",
            description="GDPR requirements for AI systems processing personal data",
            rules=[
                PolicyRule(
                    id="gdpr_001",
                    name="Lawful Basis",
                    description="Processing personal data requires documented lawful basis",
                    category="privacy",
                    severity=Severity.CRITICAL,
                    check_type="conditional",
                    check_config={
                        "condition_field": "processes_personal_data",
                        "check_field": "lawful_basis_documented",
                        "expected": True
                    }
                ),
                PolicyRule(
                    id="gdpr_002",
                    name="Data Minimization",
                    description="Only collect data necessary for the stated purpose",
                    category="privacy",
                    severity=Severity.HIGH,
                    check_type="boolean",
                    check_config={"field": "data_minimization", "expected": True}
                ),
                PolicyRule(
                    id="gdpr_003",
                    name="Right to Explanation",
                    description="Automated decisions affecting individuals must be explainable",
                    category="transparency",
                    severity=Severity.HIGH,
                    check_type="conditional",
                    check_config={
                        "condition_field": "automated_decisions",
                        "check_field": "explainability",
                        "expected": True
                    }
                ),
                PolicyRule(
                    id="gdpr_004",
                    name="Consent for Profiling",
                    description="Profiling requires explicit consent",
                    category="privacy",
                    severity=Severity.CRITICAL,
                    check_type="conditional",
                    check_config={
                        "condition_field": "performs_profiling",
                        "check_field": "profiling_consent",
                        "expected": True
                    }
                ),
            ]
        )
        
        # NIST AI RMF
        self._policy_packs["nist_ai_rmf"] = PolicyPack(
            name="NIST AI RMF",
            region="US",
            category="framework",
            version="1.0.0",
            description="NIST AI Risk Management Framework compliance",
            rules=[
                PolicyRule(
                    id="nist_001",
                    name="GOVERN: AI Governance",
                    description="Establish AI governance structure and policies",
                    category="accountability",
                    severity=Severity.HIGH,
                    check_type="boolean",
                    check_config={"field": "governance_established", "expected": True}
                ),
                PolicyRule(
                    id="nist_002",
                    name="MAP: Context Understanding",
                    description="Document AI system context and intended use",
                    category="transparency",
                    severity=Severity.MEDIUM,
                    check_type="boolean",
                    check_config={"field": "context_documented", "expected": True}
                ),
                PolicyRule(
                    id="nist_003",
                    name="MEASURE: Risk Assessment",
                    description="Quantify and assess AI system risks",
                    category="accountability",
                    severity=Severity.HIGH,
                    check_type="boolean",
                    check_config={"field": "risk_assessed", "expected": True}
                ),
                PolicyRule(
                    id="nist_004",
                    name="MANAGE: Risk Treatment",
                    description="Implement controls for identified risks",
                    category="security",
                    severity=Severity.HIGH,
                    check_type="boolean",
                    check_config={"field": "controls_implemented", "expected": True}
                ),
            ]
        )
    
    def _parse_policy(self, data: Dict[str, Any]) -> PolicyPack:
        """Parse policy JSON into PolicyPack object."""
        rules = [
            PolicyRule(
                id=r["id"],
                name=r["name"],
                description=r["description"],
                category=r["category"],
                severity=Severity(r["severity"]),
                check_type=r["check_type"],
                check_config=r.get("check_config", {}),
            )
            for r in data.get("rules", [])
        ]
        
        return PolicyPack(
            name=data["name"],
            region=data["region"],
            category=data["category"],
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            rules=rules,
            enabled=data.get("enabled", True),
        )
    
    def get_policies_for_region(self, region: str) -> List[PolicyPack]:
        """Get all applicable policies for a region."""
        region_upper = region.upper()
        policy_names = self.REGION_POLICIES.get(region_upper, ["internal_baseline"])
        
        # Always include global baseline
        if "internal_baseline" not in policy_names:
            policy_names = ["internal_baseline"] + policy_names
        
        policies = []
        for name in policy_names:
            if name in self._policy_packs:
                policies.append(self._policy_packs[name])
        
        return policies
    
    def _evaluate_rule(
        self,
        rule: PolicyRule,
        system_details: Dict[str, Any],
    ) -> EvaluationResult:
        """Evaluate a single rule against system details."""
        config = rule.check_config
        
        if rule.check_type == "boolean":
            # Simple boolean check
            field = config.get("field", "")
            expected = config.get("expected", True)
            actual = system_details.get(field)
            
            passed = actual == expected
            message = f"✓ {rule.name}" if passed else f"✗ {rule.name}: Expected {field}={expected}, got {actual}"
            
        elif rule.check_type == "conditional":
            # Conditional check - only applies if condition is met
            condition_field = config.get("condition_field", "")
            condition_value = config.get("condition_value")
            check_field = config.get("check_field", "")
            expected = config.get("expected", True)
            
            actual_condition = system_details.get(condition_field)
            
            # Check if condition applies
            if condition_value is not None:
                if isinstance(condition_value, list):
                    condition_met = actual_condition in condition_value
                else:
                    condition_met = actual_condition == condition_value
            else:
                condition_met = bool(actual_condition)
            
            if not condition_met:
                # Condition not met - rule passes (not applicable)
                return EvaluationResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    passed=True,
                    severity=rule.severity.value,
                    message=f"✓ {rule.name}: Not applicable (condition not met)",
                    details={"condition_met": False}
                )
            
            # Condition met - check the actual field
            actual = system_details.get(check_field)
            passed = actual == expected
            message = f"✓ {rule.name}" if passed else f"✗ {rule.name}: Required {check_field}={expected} when {condition_field}={actual_condition}"
            
        elif rule.check_type == "threshold":
            # Numeric threshold check
            field = config.get("field", "")
            operator = config.get("operator", "<=")
            threshold = config.get("threshold", 0)
            actual = system_details.get(field, 0)
            
            if operator == "<=":
                passed = actual <= threshold
            elif operator == ">=":
                passed = actual >= threshold
            elif operator == "<":
                passed = actual < threshold
            elif operator == ">":
                passed = actual > threshold
            else:
                passed = actual == threshold
            
            message = f"✓ {rule.name}" if passed else f"✗ {rule.name}: {field}={actual} fails threshold {operator} {threshold}"
            
        elif rule.check_type == "list_contains":
            # Check if list contains required items
            field = config.get("field", "")
            required = config.get("required", [])
            actual = system_details.get(field, [])
            
            missing = [r for r in required if r not in actual]
            passed = len(missing) == 0
            message = f"✓ {rule.name}" if passed else f"✗ {rule.name}: Missing {missing}"
            
        else:
            # Unknown check type
            passed = True
            message = f"⚠ {rule.name}: Unknown check type '{rule.check_type}'"
        
        return EvaluationResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=passed,
            severity=rule.severity.value,
            message=message,
        )
    
    def evaluate(
        self,
        system_name: str,
        region: str,
        system_details: Dict[str, Any],
    ) -> PolicyEvaluation:
        """
        Evaluate a system against all applicable policies.
        
        Args:
            system_name: Name of the system being evaluated
            region: Deployment region (determines applicable policies)
            system_details: System metadata for evaluation
        
        Returns:
            PolicyEvaluation with pass/fail results
        """
        policies = self.get_policies_for_region(region)
        
        passed_rules = []
        failed_rules = []
        warnings = []
        
        for policy in policies:
            if not policy.enabled:
                continue
            
            for rule in policy.rules:
                result = self._evaluate_rule(rule, system_details)
                
                if result.passed:
                    passed_rules.append(result)
                else:
                    failed_rules.append(result)
                    
                    # Add warning for critical/high severity failures
                    if rule.severity in [Severity.CRITICAL, Severity.HIGH]:
                        warnings.append(f"[{policy.name}] {result.message}")
        
        # Overall compliance: no critical failures
        critical_failures = [f for f in failed_rules if f.severity == "critical"]
        overall_compliant = len(critical_failures) == 0
        
        return PolicyEvaluation(
            system_name=system_name,
            region=region,
            policies_evaluated=[p.name for p in policies],
            passed_rules=passed_rules,
            failed_rules=failed_rules,
            warnings=warnings,
            overall_compliant=overall_compliant,
        )
    
    def list_policies(self) -> List[Dict[str, Any]]:
        """List all available policy packs."""
        return [p.to_dict() for p in self._policy_packs.values()]
    
    def get_policy(self, name: str) -> Optional[PolicyPack]:
        """Get a specific policy pack by name."""
        return self._policy_packs.get(name.lower().replace(" ", "_"))


# Singleton instance
_policy_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    """Get or create the policy engine singleton."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine
