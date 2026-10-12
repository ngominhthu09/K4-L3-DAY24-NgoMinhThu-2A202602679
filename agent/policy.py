"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path


_PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


def _deny(reason: str) -> tuple[bool, str]:
    return False, reason


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    # This is an invariant: authorized identity and scopes cannot override it.
    if context.data_classification == "restricted" and context.egress_enabled:
        return _deny("restricted data cannot use egress")

    if context.data_classification not in {"public", "internal", "restricted"}:
        return _deny("unknown data classification")
    if context.delegation_depth < 0:
        return _deny("delegation depth cannot be negative")
    if not context.principal_id:
        return _deny("principal is missing")

    try:
        principals = json.loads(_PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _deny("trusted principal registry is unavailable")
    principal = principals.get(context.principal_id)
    if principal is None:
        return _deny("unknown principal")

    if not context.requested_tool:
        return _deny("requested tool is missing")
    if context.requested_tool not in principal.get("allowed_tools", []):
        return _deny("tool is not allowed for principal")
    if context.requested_tool not in context.agent_scopes:
        return _deny("tool is outside agent scope")
    if context.delegation_depth > 0 and context.requested_tool not in context.parent_scopes:
        return _deny("tool is outside parent delegation scope")
    if context.request_purpose not in principal.get("purposes", []):
        return _deny("purpose is not allowed for principal")
    if not context.agent_owner:
        return _deny("agent owner is missing")

    try:
        expiry_text = context.expires_at
        expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            return _deny("expiry must include a timezone")
        if expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            return _deny("delegated run has expired")
    except (TypeError, ValueError):
        return _deny("expiry is missing or invalid")

    return True, "principal, purpose, scope, and expiry are valid"
