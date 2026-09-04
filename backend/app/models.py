"""
Pydantic schemas and enums for request/response validation.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr


class DiagnosticModuleEnum(str, Enum):
    VACUUM_WRAPAROUND = "vacuum_wraparound"
    RLS_DEBUG = "rls_debug"
    CONNECTION_HEALTH = "connection_health"
    STORAGE_AUDIT = "storage_audit"
    SLOW_QUERIES = "slow_queries"


class SeverityEnum(str, Enum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ScanStatusEnum(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DataShapeSourceEnum(str, Enum):
    """Which connection produced a data-shape finding, or that none could."""

    NOT_RUN = "not_run"          # no connection could read rows; result is INDETERMINATE
    READ_ONLY = "read_only"      # the standard read-only diagnostic connection
    ELEVATED = "elevated"        # the opt-in TARGET_ELEVATED_DATABASE_URL connection


class RowVisibilityEnum(str, Enum):
    """
    Why the diagnostic role can or cannot see rows. These four states look identical
    from a bare `count(*) = 0` but call for entirely different remediation, so they
    are reported separately.
    """

    NO_PRIVILEGE = "no_privilege"            # no SELECT grant at all
    NO_POLICY_APPLIES = "no_policy_applies"  # policies exist but none targets this role;
                                             # the planner proves it statically
    RLS_FILTERED = "rls_filtered"            # a policy applies, and it filtered every row
    READABLE = "readable"                    # rows are visible
    UNKNOWN = "unknown"                      # the read could not be completed


# Auth Models
class MagicLinkRequest(BaseModel):
    email: EmailStr


class MagicLinkResponse(BaseModel):
    status: str = "sent"
    message: str = "Magic link sent to your email address."


class AuthCallbackResponse(BaseModel):
    user_id: str
    email: Optional[str] = None
    org_id: Optional[str] = None
    token: str


class UserProfile(BaseModel):
    id: UUID
    org_id: UUID
    email: Optional[str] = None
    role: str = "member"


# Target Connection Models
class TargetConnectionCreate(BaseModel):
    label: str = Field(..., description="Human-readable label for the target database")
    host: str = Field(..., description="Postgres host or Supabase pooler host")
    port: int = Field(default=5432, description="Postgres port (e.g. 5432 or 6543)")
    db_name: str = Field(default="postgres", description="Target database name")
    db_user: str = Field(default="postgres", description="Database user (read-only diagnostic role recommended)")
    password: str = Field(..., description="Database password (will be vaulted securely, never stored plaintext)")
    ssl: bool = Field(default=True, description="Enforce SSL connection")


class TargetConnectionResponse(BaseModel):
    id: UUID
    org_id: UUID
    label: str
    host: str
    port: int
    db_name: str
    db_user: str
    secret_id: UUID
    created_at: datetime


# Diagnostic & Scan Models
class DiagnosticSummary(BaseModel):
    module: DiagnosticModuleEnum
    severity: SeverityEnum
    summary: str
    raw_result: Any
    ai_explanation: Optional[str] = None
    ai_provider: Optional[str] = Field(
        None,
        description="Which LLM produced ai_explanation ('gemini', 'ollama'). None when narration was unavailable. Never hardcode a vendor name in the UI -- read this.",
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanRunResponse(BaseModel):
    id: UUID
    target_connection_id: UUID
    status: ScanStatusEnum
    started_at: datetime
    completed_at: Optional[datetime] = None
    results: List[DiagnosticSummary] = []
    error_message: Optional[str] = None
    persisted: bool = Field(
        False,
        description="Whether this run was written to the control-plane database. False means it exists only in this process and will not survive a restart.",
    )


# RLS Debug Models
class RLSDebugRequest(BaseModel):
    connection_id: Optional[UUID] = None
    table_name: str = Field(..., description="Table name in public schema to inspect")


class RLSPolicyInfo(BaseModel):
    schemaname: str
    tablename: str
    policyname: str
    permissive: str
    roles: List[str]
    cmd: str
    qual: Optional[str] = None
    with_check: Optional[str] = None


class RLSDebugResponse(BaseModel):
    """
    Everything here is something the inspector actually observed. Fields that
    would describe work the module does not perform (a simulated user, a rolled
    back transaction, a row count it never had access to) are deliberately absent
    rather than stubbed, so a caller cannot mistake a placeholder for a result.
    """

    table_name: str
    rls_enabled: bool
    policies_found: List[RLSPolicyInfo]
    plan: Any
    has_select_privilege: bool = Field(
        ..., description="Whether the diagnostic role holds SELECT on the table (a GRANT, independent of RLS)"
    )
    row_visibility: RowVisibilityEnum = Field(
        ..., description="Why the diagnostic role can or cannot see rows"
    )
    plan_proves_zero_rows: bool = Field(
        False,
        description="True when the planner collapsed the query to a constant-false filter, proving no row is visible to this role without reading the heap",
    )
    policy_roles: List[str] = Field(
        [], description="Distinct roles targeted by the policies on this table"
    )
    applicable_policy_count: int = Field(
        0, description="Policies whose target roles include the connecting role (or PUBLIC)"
    )
    readable_rows_count: Optional[int] = Field(
        None, description="Rows visible to the diagnostic role under RLS; None when the read could not be attempted"
    )
    reltuples_estimate: Optional[int] = Field(
        None, description="pg_class row estimate; None when the table has never been analyzed"
    )
    data_shape_source: DataShapeSourceEnum = Field(
        ..., description="Which connection produced the data-shape findings, or that none could"
    )
    data_shape_checked_columns: List[str] = []
    detected_issues: List[str] = []
    ai_explanation: str
    execution_time_ms: float


# Assistant & Chat Models
class ToolCallTrace(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    tool_name: str
    arguments: Dict[str, Any]
    result: Any
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ChatMessageRequest(BaseModel):
    content: str
    connection_id: Optional[UUID] = None


class ChatMessageResponse(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    role: str
    content: str
    tool_calls: List[ToolCallTrace] = []
    provider: str = Field(
        "none",
        description="Which LLM answered ('gemini', 'ollama'), or 'none' when the reply came from deterministic routing.",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ProviderStatusResponse(BaseModel):
    name: str
    configured: bool
    available: bool
    model: Optional[str] = None
    detail: str


class ProviderSelectionResponse(BaseModel):
    selected: str = Field(..., description="Provider selection in force: auto, gemini, ollama, or none")
    source: str = Field(..., description="'runtime override' or 'configuration'")
    providers: List[ProviderStatusResponse] = []


class ProviderSelectionRequest(BaseModel):
    provider: str = Field(..., description="auto | gemini | ollama | none")


# Report Models
class ReportFinding(BaseModel):
    """
    One diagnostic finding, prepared for reporting.

    Diagnosis only: no remediation, no suggested fixes, no SQL. `probable_cause` is
    derived in Python from the diagnostic payload; `ai_explanation` is narration,
    carried beside it and never a source of any other field here.
    """

    module: str
    severity: str
    summary: str
    affected: Dict[str, str] = Field(
        {}, description="The affected object as structured fields: table, policy, column, role"
    )
    probable_cause: Optional[str] = Field(
        None, description="Computed from the diagnostic data. Never LLM-generated."
    )
    scope_caveat: Optional[str] = Field(
        None, description="What the check could not cover, as recorded by the module"
    )
    observations: List[str] = []
    raw_result: Any = None
    ai_explanation: Optional[str] = None
    ai_provider: Optional[str] = None


class ScanRunSummary(BaseModel):
    """One row of the reports index."""

    id: UUID
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: ScanStatusEnum
    target_connection_id: UUID
    target_label: Optional[str] = None
    target_host: Optional[str] = None
    worst_severity: Optional[str] = None
    module_count: int = 0


class ScanReport(BaseModel):
    run: ScanRunSummary
    findings: List[ReportFinding] = []
    severity_counts: Dict[str, int] = {}
