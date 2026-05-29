"""
AEGIS Pydantic Schemas
Request/Response validation schemas for all API endpoints.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field


# =============================================================================
# Common Schemas
# =============================================================================

class StatusResponse(BaseModel):
    """Standard status response."""
    status: str = "ok"
    message: str = ""


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


# =============================================================================
# Filter Schemas (Guardrails)
# =============================================================================

class FilterRequest(BaseModel):
    """Request to filter text through guardrails."""
    text: str = Field(..., min_length=1, max_length=50000, description="Text to filter")
    direction: Literal["prompt", "response"] = Field(
        default="prompt", 
        description="Whether filtering input prompt or model response"
    )
    filters: Optional[List[str]] = Field(
        default=None,
        description="Specific filters to apply. If None, applies all."
    )
    system_name: Optional[str] = Field(default=None, description="System name for logging")
    tier: Literal[1, 2, "both"] = Field(
        default="both",
        description="Which tier to run: 1 (fast regex/YARA), 2 (LLM), or both"
    )


class FilterMatch(BaseModel):
    """A single filter match result."""
    filter_name: str
    category: str  # pii, jailbreak, injection, toxicity
    matched_text: str
    replacement: Optional[str] = None
    confidence: float = Field(ge=0, le=1)
    tier: int


class FilterResponse(BaseModel):
    """Response from filter endpoint."""
    original_text: str
    filtered_text: str
    blocked: bool = False
    block_reason: Optional[str] = None
    matches: List[FilterMatch] = []
    tier1_latency_ms: float
    tier2_latency_ms: Optional[float] = None
    total_latency_ms: float


# =============================================================================
# Risk Scoring Schemas
# =============================================================================

class RiskScoreRequest(BaseModel):
    """Request to score an AI system's risk."""
    system_name: str = Field(..., min_length=1, max_length=100)
    
    # Data Sensitivity signals (25% weight)
    pii_involved: bool = False
    pii_types: List[str] = []  # email, ssn, health, financial, etc.
    data_volume: Literal["low", "medium", "high", "very_high"] = "medium"
    cross_border_transfer: bool = False
    
    # Autonomy Level signals (20% weight)
    autonomy_level: Literal["advisory", "human_in_loop", "supervised_auto", "fully_autonomous"] = "advisory"
    decision_type: Optional[str] = None  # recommendation, classification, generation, action
    
    # Impact Scope signals (20% weight)
    affected_users: Literal["internal_only", "limited", "broad", "public"] = "limited"
    vulnerable_populations: bool = False
    critical_infrastructure: bool = False
    
    # Model Risk signals (15% weight)
    model_type: Optional[str] = None  # classification, generation, embedding, etc.
    training_data_provenance: Literal["unknown", "partial", "documented", "verified"] = "unknown"
    
    # Regulatory Exposure signals (10% weight)
    applicable_regulations: List[str] = []  # gdpr, hipaa, ccpa, etc.
    high_risk_classification: bool = False
    
    # Organizational Readiness signals (10% weight)
    existing_controls: Literal["none", "basic", "moderate", "comprehensive"] = "basic"
    team_training: bool = False
    incident_response_plan: bool = False


class RiskBreakdown(BaseModel):
    """Breakdown of risk score by category."""
    data_sensitivity: float = Field(ge=0, le=100)
    autonomy_level: float = Field(ge=0, le=100)
    impact_scope: float = Field(ge=0, le=100)
    model_risk: float = Field(ge=0, le=100)
    regulatory_exposure: float = Field(ge=0, le=100)
    organizational_readiness: float = Field(ge=0, le=100)


class RiskScoreResponse(BaseModel):
    """Risk scoring result."""
    system_name: str
    score: float = Field(ge=0, le=100)
    level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    breakdown: RiskBreakdown
    recommendations: List[str]
    assessed_at: datetime


# =============================================================================
# Policy Schemas
# =============================================================================

class PolicyRule(BaseModel):
    """A single policy rule."""
    id: str
    name: str
    description: str
    category: str  # transparency, fairness, accountability, privacy, security
    severity: Literal["low", "medium", "high", "critical"]
    check_type: str  # boolean, threshold, regex, custom
    check_config: Dict[str, Any] = {}


class PolicyCreate(BaseModel):
    """Create a new policy template."""
    name: str = Field(..., min_length=1, max_length=100)
    region: str = Field(..., min_length=1, max_length=50)
    category: str
    description: Optional[str] = None
    rules: List[PolicyRule]


class PolicyResponse(BaseModel):
    """Policy template response."""
    id: int
    name: str
    region: str
    category: str
    version: str
    description: Optional[str]
    rules: List[Dict[str, Any]]
    enabled: bool
    created_at: datetime


class PolicyEvaluateRequest(BaseModel):
    """Request to evaluate a system against policies."""
    system_name: str
    region: str
    system_details: Dict[str, Any]  # System metadata for evaluation


class PolicyEvaluationResult(BaseModel):
    """Result of a single policy rule evaluation."""
    rule_id: str
    rule_name: str
    passed: bool
    severity: str
    message: str


class PolicyEvaluateResponse(BaseModel):
    """Response from policy evaluation."""
    system_name: str
    region: str
    policies_evaluated: List[str]
    passed_rules: List[PolicyEvaluationResult]
    failed_rules: List[PolicyEvaluationResult]
    warnings: List[str]
    overall_compliant: bool


# =============================================================================
# Audit Schemas
# =============================================================================

class AuditLogRequest(BaseModel):
    """Request to log an audit event."""
    event_type: str = Field(..., min_length=1, max_length=50)
    actor: str = Field(..., min_length=1, max_length=100)
    system_name: Optional[str] = None
    details: Dict[str, Any] = {}


class AuditLogResponse(BaseModel):
    """Single audit log entry."""
    id: int
    timestamp: datetime
    event_type: str
    actor: str
    system_name: Optional[str]
    details: Dict[str, Any]
    hash: str
    prev_hash: str


class AuditTrailResponse(BaseModel):
    """Audit trail response with multiple entries."""
    entries: List[AuditLogResponse]
    total: int
    verified: bool
    verification_message: str


class AuditVerifyResponse(BaseModel):
    """Audit chain verification result."""
    verified: bool
    total_entries: int
    first_entry_hash: str
    last_entry_hash: str
    message: str
    tampered_entries: List[int] = []


# =============================================================================
# Red Team Schemas
# =============================================================================

class RedTeamRequest(BaseModel):
    """Request to run red team tests."""
    target_model: str = Field(default="gemini-2.0-flash")
    categories: List[Literal["jailbreak", "pii", "bias", "hallucination", "injection"]] = Field(
        default=["jailbreak", "pii", "injection"]
    )
    system_name: Optional[str] = None


class RedTeamProbeResult(BaseModel):
    """Result of a single red team probe."""
    category: str
    probe: str
    response: str
    passed: bool
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    details: Dict[str, Any] = {}


class RedTeamResponse(BaseModel):
    """Red team test suite response."""
    target_model: str
    categories_tested: List[str]
    total_probes: int
    passed: int
    failed: int
    results: List[RedTeamProbeResult]
    run_at: datetime


# =============================================================================
# DPIA Schemas
# =============================================================================

class DPIARequest(BaseModel):
    """Request to generate a DPIA report."""
    system_name: str
    description: str
    data_types: List[str]
    purpose: str
    processing_operations: Optional[List[str]] = None
    recipients: Optional[List[str]] = None
    retention_period: Optional[str] = None
    security_measures: Optional[List[str]] = None


class DPIASection(BaseModel):
    """A section of the DPIA report."""
    title: str
    content: str


class DPIAResponse(BaseModel):
    """DPIA report response."""
    id: int
    system_name: str
    sections: List[DPIASection]
    risk_summary: str
    recommendations: List[str]
    generated_at: datetime
    status: str


# =============================================================================
# Dashboard Schemas
# =============================================================================

class DashboardStats(BaseModel):
    """Dashboard statistics."""
    total_systems: int
    high_risk_systems: int
    total_filter_requests: int
    blocked_requests: int
    policy_compliance_rate: float
    recent_audits: int
    active_playbooks: int


class RiskHeatmapEntry(BaseModel):
    """Entry for risk heatmap visualization."""
    system_name: str
    risk_level: str
    score: float
    last_assessed: datetime


class DashboardResponse(BaseModel):
    """Full dashboard data response."""
    stats: DashboardStats
    risk_heatmap: List[RiskHeatmapEntry]
    recent_activity: List[Dict[str, Any]]


class LogsDashboardSummary(BaseModel):
    """Aggregated metrics for the admin logs dashboard."""
    period_days: int
    total_audit_events: int
    total_filter_requests: int
    blocked_filter_requests: int
    analyze_total: int
    analyze_allowed: int
    analyze_blocked: int
    pii_detections: int
    jailbreak_detections: int
    injection_detections: int
    toxicity_detections: int
    chat_sessions: int = 0
    chat_messages: int = 0


class LogsTrafficDay(BaseModel):
    """Daily traffic bucket for charts."""
    date: str
    audit_events: int
    filter_requests: int
    blocked: int
    pii_hits: int


class LogsDashboardRates(BaseModel):
    """Percentage rates for dashboard health cards."""
    analyze_block_rate: float = 0.0
    filter_block_rate: float = 0.0
    pii_hit_rate: float = 0.0


class LogsActorCount(BaseModel):
    actor: str
    count: int


class LogsDashboardResponse(BaseModel):
    """Admin telemetry dashboard payload."""
    viewer: str
    period_days: int
    generated_at: datetime
    summary: LogsDashboardSummary
    rates: LogsDashboardRates
    top_actors: List[LogsActorCount]
    event_type_counts: Dict[str, int]
    pii_by_type: Dict[str, int]
    threat_by_category: Dict[str, int]
    traffic_by_day: List[LogsTrafficDay]
    inference_by_provider: Dict[str, int]
    region_breakdown: Dict[str, int]
    direction_breakdown: Dict[str, int]
    recent_entries: List[Dict[str, Any]]


# =============================================================================
# Playbook Schemas
# =============================================================================

PLAYBOOK_STAGES = ["INTAKE", "RISK_ASSESSMENT", "POLICY_CHECK", "REVIEW", "APPROVED", "ATTESTED"]


class PlaybookRunRequest(BaseModel):
    """Request to start a governance playbook."""
    system_name: str
    owner: str
    region: str
    extra_data: Dict[str, Any] = {}


class PlaybookStatusResponse(BaseModel):
    """Playbook status response."""
    id: int
    system_name: str
    owner: str
    region: str
    current_stage: str
    stages_completed: Dict[str, Any]
    next_stage: Optional[str]
    created_at: datetime
    updated_at: datetime


class PlaybookAdvanceRequest(BaseModel):
    """Request to advance playbook to next stage."""
    playbook_id: int
    notes: Optional[str] = None
    approved_by: Optional[str] = None


# =============================================================================
# Proxy Schemas (for forwarding to Gemini)
# =============================================================================

class ProxyRequest(BaseModel):
    """Request to proxy a prompt through AEGIS to Gemini."""
    prompt: str = Field(..., min_length=1, max_length=100000)
    system_name: Optional[str] = None
    region: Optional[str] = "global"
    guardrail_mode: str = Field(
        default="rule_based",
        description="Input guardrail mode: 'none' (no checks), 'rule_based' (Tier 1, <30ms), 'model_based' (Tier 1+2, ~5s)"
    )
    output_guardrail_mode: Literal["none", "tier1", "tier2"] = Field(
        default="tier1",
        description="Output guardrail mode: 'none', 'tier1' (warn-only checks), 'tier2' (compliance assessment)"
    )
    inference_provider: Literal["gemini", "openrouter", "huggingface", "mistral"] = Field(
        default="gemini",
        description="Inference provider to use for response generation",
    )
    model: str = "gemini-2.5-flash"


class ProxyResponse(BaseModel):
    """Response from proxied Gemini call."""
    original_prompt: str
    filtered_prompt: str
    model_response: str
    filtered_response: str
    guardrail_results: Optional[FilterResponse] = None
    output_guardrail: Optional["OutputGuardrailResult"] = None
    policy_check: Optional[Dict[str, Any]] = None
    # Timing breakdown
    total_time_ms: float  # Total end-to-end time
    guardrail_latency_ms: float  # Time added by guardrails
    model_time_ms: float  # Time for Gemini to respond
    blocked: bool = False
    block_reason: Optional[str] = None


# =============================================================================
# Two-Tier Analysis Schemas
# =============================================================================

class AnalyzeRequest(BaseModel):
    """Request for two-tier progressive analysis."""
    prompt: str = Field(..., min_length=1, max_length=100000)
    region: Literal["india", "china", "europe", "usa", "australia"] = Field(
        default="india",
        description="Region for policy enforcement"
    )
    guardrail_mode: Literal["basic", "advanced"] = Field(
        default="basic",
        description="Input: basic = Tier 1 only (<30ms), advanced = Tier 1 + Tier 2 (~5s)"
    )
    output_guardrail_mode: Literal["none", "tier1", "tier2"] = Field(
        default="tier1",
        description="Output: 'none', 'tier1' (warn-only), 'tier2' (compliance assessment)"
    )
    inference_provider: Literal["gemini", "openrouter", "huggingface", "mistral"] = Field(
        default="gemini",
        description="Inference provider to use for response generation",
    )
    model: str = Field(
        default="gemini-2.5-flash",
        description="Provider-specific API model id (from /inference/options)",
    )


class InferenceModelOption(BaseModel):
    id: str
    label: str
    api_model: str


class InferenceProviderOption(BaseModel):
    provider: str
    available: bool
    models: List[InferenceModelOption]
    hint: str = ""


class InferenceOptionsResponse(BaseModel):
    providers: List[InferenceProviderOption]


class Tier1Result(BaseModel):
    """Tier 1 fast scan results."""
    blocked: bool = False
    block_reason: Optional[str] = None
    matches: List[FilterMatch] = []
    identified_entities: List[str] = Field(
        default_factory=list,
        description="Entity types detected (no raw matched content when blocked)",
    )
    filtered_text: str
    latency_seconds: float


class Tier2Result(BaseModel):
    """Tier 2 deep analysis results."""
    blocked: bool = False
    block_reason: Optional[str] = None
    policies_applied: List[str] = []
    region: str
    latency_seconds: float


# =============================================================================
# Output Guardrail Schemas
# =============================================================================

class OutputFinding(BaseModel):
    """A single finding from output guardrail analysis."""
    category: str  # pii, toxicity, insecure_code, bias, compliance
    severity: Literal["info", "warning", "critical"]
    description: str
    matched_text: Optional[str] = None
    confidence: float = Field(ge=0, le=1)


class OutputTier1Result(BaseModel):
    """Output Tier 1: Pattern-based warning scan (no blocking)."""
    findings: List[OutputFinding] = []
    has_warnings: bool = False
    warning_summary: Optional[str] = None
    latency_ms: float


class OutputTier2Result(BaseModel):
    """Output Tier 2: LLM-based compliance and safety assessment."""
    compliant: bool = True
    safety_score: float = Field(ge=0, le=1, default=1.0, description="1.0 = fully safe, 0.0 = unsafe")
    compliance_findings: List[OutputFinding] = []
    region: str
    policies_checked: List[str] = []
    assessment: str = Field(description="Human-readable safety assessment")
    recommendations: List[str] = []
    latency_ms: float


class OutputGuardrailResult(BaseModel):
    """Combined output guardrail results."""
    tier1: Optional[OutputTier1Result] = None
    tier2: Optional[OutputTier2Result] = None
    safe_to_use: bool = True
    action_required: bool = False
    summary: str = "Output passed all checks."


class OutputReviewFinding(BaseModel):
    id: str
    category: str
    severity: str
    description: str
    matched_text: Optional[str] = None
    confidence: float = 0.0
    label: str = ""


class InputPiiEntity(BaseModel):
    """PII entity type detected in a user message (display name only)."""
    id: str
    entity_name: str
    kinds: List[str] = Field(
        default_factory=list,
        description="Human-readable PII match types found for this entity (e.g. hard/soft block)",
    )


class InputPiiConsentState(BaseModel):
    status: Literal["pending", "denied", "allowed_all", "allowed_some"] = "pending"
    entities: List[InputPiiEntity] = Field(default_factory=list)
    requires_user_action: bool = False
    user_message_id: int = 0


class ChatInputPiiConsentRequest(BaseModel):
    action: Literal["deny", "allow_all", "allow_some"]
    allowed_pii_finding_ids: List[str] = Field(
        default_factory=list,
        description="Entity ids the user allows to remain in the message (allow_some only)",
    )


class OutputReviewState(BaseModel):
    status: Literal["none", "pending_review", "delivered"] = "none"
    requires_user_action: bool = False
    trigger_reasons: List[str] = Field(default_factory=list)
    max_code_confidence: Optional[float] = None
    security_threshold: float = 0.90
    code_regen_available: bool = False
    regenerations_remaining: int = 2
    regenerations_used: int = 0
    findings: List[OutputReviewFinding] = Field(default_factory=list)
    allowed_actions: List[str] = Field(default_factory=list)
    has_pii_findings: bool = False
    has_code_findings: bool = False


class AnalyzeResponse(BaseModel):
    """Final structured response from two-tier analysis."""
    allow: bool
    response: str = Field(
        description="If allowed: the actual model response. If not allowed: reason the model cannot respond."
    )
    original_prompt: str
    tier1: Tier1Result
    tier2: Optional[Tier2Result] = None
    output_guardrail: Optional[OutputGuardrailResult] = None
    total_latency_seconds: float


# =============================================================================
# Chat Schemas
# =============================================================================

class TaskBrief(BaseModel):
    goal: str = ""
    constraints: List[str] = Field(default_factory=list)
    must_not: List[str] = Field(default_factory=list)
    acceptance: str = ""
    stack: str = ""
    lessons: List[Dict[str, Any]] = Field(default_factory=list)


class ClarificationQuestion(BaseModel):
    id: str
    text: str
    choices: List[str] = Field(default_factory=list)


class ExecutionPlanStep(BaseModel):
    id: str
    label: str
    kind: Literal["local", "llm"] = "local"
    state: Literal["planned", "active", "done", "skipped", "blocked", "waiting"] = "planned"
    detail: Optional[str] = None
    llm_calls: int = 0


class ChatSessionSettings(BaseModel):
    region: Literal["india", "china", "europe", "usa", "australia"] = "india"
    guardrail_mode: Literal["basic", "advanced"] = "basic"
    output_guardrail_mode: Literal["none", "tier1", "tier2"] = "tier1"
    security_threshold_preset: Literal["strict", "balanced", "quiet"] = Field(
        default="balanced",
        description="When insecure code is found in model output, prompt regen if confidence >= this preset's value",
    )
    completion_mode: Literal["fast", "balanced", "clarify_first"] = Field(
        default="balanced",
        description="Fast: generate immediately. Balanced: clarify when vague. Clarify-first: questions before first generation.",
    )
    inference_provider: Literal["gemini", "openrouter", "huggingface", "mistral"] = "gemini"
    model: str = "gemini-2.0-flash"


class ChatSessionCreate(ChatSessionSettings):
    title: Optional[str] = "New chat"


class ChatSessionUpdate(ChatSessionSettings):
    title: Optional[str] = None


class ChatSessionResponse(BaseModel):
    id: int
    title: str
    region: str
    guardrail_mode: str
    output_guardrail_mode: str
    security_threshold_preset: str = "balanced"
    security_threshold: float = 0.90
    completion_mode: str = "balanced"
    phase: str = "idle"
    task_brief: TaskBrief = Field(default_factory=TaskBrief)
    execution_plan: List[ExecutionPlanStep] = Field(default_factory=list)
    planned_llm_calls: int = 0
    clarification_questions: List[ClarificationQuestion] = Field(default_factory=list)
    inference_provider: str
    model: str
    created_at: datetime
    updated_at: datetime
    message_count: int = 0


class ChatTaskBriefUpdate(BaseModel):
    goal: Optional[str] = None
    constraints: Optional[List[str]] = None
    must_not: Optional[List[str]] = None
    acceptance: Optional[str] = None
    stack: Optional[str] = None


class ChatClarifyRequest(BaseModel):
    answers: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of question id → answer text",
    )
    continue_generation: bool = Field(
        default=True,
        description="After merging answers, run the pending governed generation",
    )


class PipelineStepState(BaseModel):
    id: str
    label: str
    state: Literal["waiting", "active", "done", "blocked", "skipped"]
    detail: Optional[str] = None
    latency_ms: Optional[float] = None


class ChatMessageResponse(BaseModel):
    id: int
    role: Literal["user", "assistant"]
    content: Optional[str] = None
    storage_mode: Literal["full", "redacted", "withheld"] = "full"
    allow: Optional[bool] = None
    pipeline: List[PipelineStepState] = []
    requires_clarification: bool = False
    clarification_questions: List[ClarificationQuestion] = Field(default_factory=list)
    identified_entities: List[str] = []
    input_pii_consent: Optional[InputPiiConsentState] = None
    requires_input_pii_consent: bool = False
    input_pii_user_message_id: Optional[int] = None
    output_guardrail: Optional[OutputGuardrailResult] = None
    output_review: Optional[OutputReviewState] = None
    preview_content: Optional[str] = Field(
        default=None,
        description="Raw model output shown only while review is pending",
    )
    created_at: datetime
    ephemeral_display: Optional[str] = Field(
        default=None,
        description="One-time UI text for withheld user messages (not stored server-side)",
    )


class ChatMessageResolveRequest(BaseModel):
    action: Literal["accept", "regenerate", "apply_pii_redaction"]
    allowed_pii_finding_ids: List[str] = Field(
        default_factory=list,
        description="PII finding ids the user allows to remain; others are redacted",
    )


class ChatSendMessageRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=100000)


class ChatSendMessageResponse(BaseModel):
    user_message: ChatMessageResponse
    assistant_message: ChatMessageResponse
    session_id: int
    phase: str = "idle"
    execution_plan: List[ExecutionPlanStep] = Field(default_factory=list)
    planned_llm_calls: int = 0
    task_brief: TaskBrief = Field(default_factory=TaskBrief)
