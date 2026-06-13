"""Canonical SessionState and all nested models (Pydantic v2).

The SessionState is the single source of truth for a security investigation.
Provider-specific chat formats are derived from it and never replace it, which
is what makes a session resumable with a *different* model at any step.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# --- Shared type aliases ----------------------------------------------------

Severity = Literal["info", "low", "medium", "high", "critical"]
RiskLevel = Literal["low", "medium", "high", "critical"]
DataSensitivity = Literal["public", "internal", "confidential", "restricted"]
SessionStatus = Literal[
    "created", "planning", "running", "paused",
    "waiting_approval", "failed", "completed",
]

ALERT_CLASSIFICATIONS = [
    "True Positive - Actionable",
    "True Positive - Non-Actionable",
    "True Positive - Risk Already Managed",
    "Benign True Positive",
    "False Positive",
    "Duplicate Alert",
    "Policy Violation",
    "Needs More Information",
    "Suspicious - Monitoring Required",
    "Confirmed Incident",
]

INCIDENT_CATEGORIES = [
    "Compromise", "Information Breach", "Network Attack",
    "OS and Application Attack", "Malware Infection",
    "Malicious Authentication Activity", "Email Security Threat",
    "Web Security Threat", "ISMS Policy Violation",
    "Vulnerability Exploitation", "Data Exfiltration",
    "Cloud Security Incident", "Insider Threat", "Reconnaissance",
    "Command and Control", "Lateral Movement", "Privilege Escalation",
]


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


# --- Task graph -------------------------------------------------------------


class TaskStep(BaseModel):
    step_id: str = Field(default_factory=_uuid)
    name: str
    description: str = ""
    agent: str
    task_type: str
    depends_on: list[str] = Field(default_factory=list)
    status: Literal["pending", "running", "completed", "failed", "skipped"] = "pending"
    risk_level: RiskLevel = "low"
    data_sensitivity: DataSensitivity = "internal"
    requires_human_approval: bool = False
    selected_model: str | None = None
    result_summary: str | None = None


class TaskGraph(BaseModel):
    goal: str = ""
    steps: list[TaskStep] = Field(default_factory=list)

    def get(self, step_id: str) -> TaskStep | None:
        return next((s for s in self.steps if s.step_id == step_id), None)


# --- Canonical conversation -------------------------------------------------


class CanonicalMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    agent: str | None = None
    model: str | None = None
    step_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Alert / incident context ----------------------------------------------


class AlertContext(BaseModel):
    alert_id: str | None = None
    alert_name: str | None = None
    severity: Severity | None = None
    source_tool: str | None = None
    detection_name: str | None = None
    detection_id: str | None = None
    event_time: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_host: str | None = None
    destination_host: str | None = None
    username: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    url: str | None = None
    domain: str | None = None
    user_agent: str | None = None
    raw_log: str | None = None
    evidence_links: list[str] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    analyst_notes: str | None = None
    customer_context: str | None = None
    asset_criticality: str | None = None
    business_impact: str | None = None
    missing_fields: list[str] = Field(default_factory=list)


class IncidentContext(BaseModel):
    incident_number: str = Field(default_factory=_uuid)
    category: str | None = None
    summary: str = ""
    declared_at: datetime = Field(default_factory=utcnow)
    status: str = "open"


class Asset(BaseModel):
    hostname: str | None = None
    ip: str | None = None
    criticality: str | None = None
    owner: str | None = None
    business_unit: str | None = None
    note: str | None = None


# --- Observables / IOCs / evidence -----------------------------------------


IOCType = Literal[
    "ip", "domain", "url", "hash", "email", "filename",
    "registry_key", "user_agent", "asn", "cve", "user", "host",
]


class IOC(BaseModel):
    ioc_id: str = Field(default_factory=_uuid)
    type: IOCType
    value: str
    context: str | None = None
    first_seen: datetime | None = None
    source: str = "extracted"


class Observable(BaseModel):
    type: str
    value: str
    context: str | None = None


class EvidenceItem(BaseModel):
    evidence_id: str = Field(default_factory=_uuid)
    type: Literal[
        "log", "screenshot", "file", "query_result", "note",
        "timeline", "threat_intel", "detection_rule", "report",
    ]
    source: str
    collected_at: datetime = Field(default_factory=utcnow)
    related_entity: str | None = None
    content: str
    hash: str | None = None
    chain_of_custody_note: str = ""
    created_by_agent: str = ""
    created_by_model: str = ""
    related_step_id: str | None = None
    version: int = 1


class TimelineEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    actor: str | None = None
    source_ip: str | None = None
    source_host: str | None = None
    destination_ip: str | None = None
    destination_host: str | None = None
    process: str | None = None
    command_line: str | None = None
    action: str | None = None
    outcome: str | None = None
    raw_reference: str | None = None
    explanation: str = ""
    confidence: float = 0.5


class Hypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=_uuid)
    statement: str
    likelihood: float = 0.5
    supporting_evidence: list[str] = Field(default_factory=list)
    refuting_evidence: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str = Field(default_factory=_uuid)
    title: str
    detail: str
    severity: Severity = "medium"
    confidence: float = 0.5
    related_entities: list[str] = Field(default_factory=list)


# --- Detection / queries / intel / MITRE ------------------------------------


class DetectionRule(BaseModel):
    rule_id: str = Field(default_factory=_uuid)
    format: str  # sigma | splunk | kql | logscale | wazuh | suricata | yara
    title: str
    description: str = ""
    logic: str = ""
    data_source: str = ""
    required_fields: list[str] = Field(default_factory=list)
    false_positive_notes: str = ""
    severity: Severity = "medium"
    mitre_mapping: list[str] = Field(default_factory=list)
    test_data: str = ""
    validation_steps: list[str] = Field(default_factory=list)
    tuning_recommendations: list[str] = Field(default_factory=list)


class GeneratedQuery(BaseModel):
    query_id: str = Field(default_factory=_uuid)
    platform: str
    use_case: str
    query: str
    notes: str = ""


class ThreatIntelResult(BaseModel):
    source: str
    observable: str
    verdict: Literal["malicious", "suspicious", "benign", "unknown"] = "unknown"
    confidence: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    raw_reference: str | None = None
    summary: str = ""


class MitreMapping(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    confidence: float = 0.5
    evidence: list[str] = Field(default_factory=list)
    explanation: str = ""


# --- Assessments / response -------------------------------------------------


class SeverityAssessment(BaseModel):
    severity: Severity
    rationale: str = ""
    impact: str = ""
    scope: str = ""


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=_uuid)
    description: str
    category: Literal["containment", "eradication", "recovery", "monitoring"]
    requires_human_approval: bool = True
    risk_level: RiskLevel = "medium"
    status: Literal["recommended", "approved", "rejected", "executed"] = "recommended"


# --- Bookkeeping ------------------------------------------------------------


class Artifact(BaseModel):
    artifact_id: str = Field(default_factory=_uuid)
    name: str
    type: str
    content: str
    created_by_agent: str = ""
    created_by_model: str = ""
    step_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class RouterDecision(BaseModel):
    """Exact router output shape from spec Section 4.2."""

    selected_agent: str
    selected_model: str
    reason: str
    confidence: float
    fallback_models: list[str] = Field(default_factory=list)
    requires_human_approval: bool = False
    risk_level: RiskLevel = "low"
    data_sensitivity: DataSensitivity = "internal"
    step_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)


class ModelCallRecord(BaseModel):
    call_id: str = Field(default_factory=_uuid)
    model: str
    agent: str
    step_id: str | None = None
    prompt_chars: int = 0
    response_chars: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=utcnow)


class ToolCallRecord(BaseModel):
    call_id: str = Field(default_factory=_uuid)
    tool: str
    agent: str = ""
    step_id: str | None = None
    input_summary: str = ""
    output_summary: str = ""
    success: bool = True
    approved: bool | None = None
    risk_level: RiskLevel = "low"
    timestamp: datetime = Field(default_factory=utcnow)


class CostSummary(BaseModel):
    total_usd: float = 0.0
    by_model: dict[str, float] = Field(default_factory=dict)


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    by_model: dict[str, int] = Field(default_factory=dict)


class CheckpointRef(BaseModel):
    checkpoint_id: str = Field(default_factory=_uuid)
    step_id: str | None = None
    label: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    diff_summary: str = ""


class RiskLogEntry(BaseModel):
    entry_id: str = Field(default_factory=_uuid)
    timestamp: datetime = Field(default_factory=utcnow)
    description: str
    risk_level: RiskLevel = "low"
    step_id: str | None = None


class ApprovalEntry(BaseModel):
    approval_id: str = Field(default_factory=_uuid)
    action: str
    step_id: str | None = None
    requested_at: datetime = Field(default_factory=utcnow)
    decided_at: datetime | None = None
    status: Literal["pending", "approved", "rejected"] = "pending"
    decided_by: str | None = None
    note: str = ""


class AuditEntry(BaseModel):
    entry_id: str = Field(default_factory=_uuid)
    timestamp: datetime = Field(default_factory=utcnow)
    actor: str
    action: str
    detail: str = ""
    step_id: str | None = None


# --- The canonical SessionState --------------------------------------------


class SessionState(BaseModel):
    session_id: str = Field(default_factory=_uuid)
    user_goal: str
    security_task_type: str = "soc_investigation"
    status: SessionStatus = "created"
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    current_step_id: str | None = None

    task_graph: TaskGraph = Field(default_factory=TaskGraph)
    completed_steps: list[TaskStep] = Field(default_factory=list)
    pending_steps: list[TaskStep] = Field(default_factory=list)
    failed_steps: list[TaskStep] = Field(default_factory=list)

    canonical_messages: list[CanonicalMessage] = Field(default_factory=list)

    alert_context: AlertContext | None = None
    incident_context: IncidentContext | None = None
    affected_assets: list[Asset] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)

    indicators_of_compromise: list[IOC] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    timeline_events: list[TimelineEvent] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    investigation_findings: list[Finding] = Field(default_factory=list)

    detection_rules: list[DetectionRule] = Field(default_factory=list)
    generated_queries: list[GeneratedQuery] = Field(default_factory=list)
    threat_intel_results: list[ThreatIntelResult] = Field(default_factory=list)
    mitre_attack_mapping: list[MitreMapping] = Field(default_factory=list)

    severity_assessment: SeverityAssessment | None = None
    confidence_assessment: float | None = None
    false_positive_reasoning: str | None = None
    true_positive_reasoning: str | None = None
    classification: str | None = None

    recommended_actions: list[str] = Field(default_factory=list)
    containment_actions: list[ResponseAction] = Field(default_factory=list)
    eradication_actions: list[ResponseAction] = Field(default_factory=list)
    recovery_actions: list[ResponseAction] = Field(default_factory=list)
    lessons_learned: list[str] = Field(default_factory=list)

    artifacts: list[Artifact] = Field(default_factory=list)
    decisions: list[RouterDecision] = Field(default_factory=list)
    model_calls: list[ModelCallRecord] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    costs: CostSummary = Field(default_factory=CostSummary)
    token_usage: TokenUsage = Field(default_factory=TokenUsage)

    checkpoints: list[CheckpointRef] = Field(default_factory=list)
    memory_summary: str | None = None

    data_sensitivity: DataSensitivity = "internal"
    risk_log: list[RiskLogEntry] = Field(default_factory=list)
    approval_log: list[ApprovalEntry] = Field(default_factory=list)
    audit_log: list[AuditEntry] = Field(default_factory=list)

    final_output: dict[str, Any] | None = None

    def touch(self) -> None:
        self.updated_at = utcnow()

    def to_json(self, *, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str) -> SessionState:
        return cls.model_validate_json(data)
