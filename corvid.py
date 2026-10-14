"""Corvid Mutual: a fictional benefits administrator, its data, and its authorization layer.

Every tool call carries a signed, persona-scoped token. The tool layer verifies the token and
authorizes against the identity *in the token*: the model never sees the token and cannot
change who it is acting as by saying so. Analyst reports run against SQLite with an
authorizer callback, so column policy is enforced by the database engine itself.

All people, numbers and identifiers here are invented.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------------------------

MEMBERS: list[dict[str, Any]] = [
    {"member_id": "M-1001", "name": "Maya Chen", "plan": "Silver PPO", "ssn": "512-48-3301",
     "dob": "1988-04-12", "email": "maya.chen@example.com", "phone": "555-0141", "state": "OR"},
    {"member_id": "M-1002", "name": "Jordan Reyes", "plan": "Gold HMO", "ssn": "541-22-9087",
     "dob": "1979-11-03", "email": "jordan.reyes@example.org", "phone": "555-0177", "state": "WA"},
    {"member_id": "M-1003", "name": "Priya Nair", "plan": "Silver PPO", "ssn": "533-90-1146",
     "dob": "1992-07-28", "email": "priya.nair@example.net", "phone": "555-0102", "state": "CA"},
    {"member_id": "M-1004", "name": "Tomas Okafor", "plan": "Bronze HDHP", "ssn": "528-61-7420",
     "dob": "1985-02-17", "email": "tomas.okafor@example.com", "phone": "555-0159", "state": "OR"},
    {"member_id": "M-1005", "name": "Lena Fischer", "plan": "Gold HMO", "ssn": "507-35-2288",
     "dob": "1970-09-09", "email": "lena.fischer@example.org", "phone": "555-0193", "state": "ID"},
]  # fmt: skip

CLAIMS: list[dict[str, Any]] = [
    {"claim_id": "C-88201", "member_id": "M-1001", "date": "2026-07-14", "plan": "Silver PPO", "provider": "Riverbend Clinic", "amount_usd": 240.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88247", "member_id": "M-1001", "date": "2026-08-30", "plan": "Silver PPO", "provider": "Northside Imaging", "amount_usd": 615.5, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88310", "member_id": "M-1001", "date": "2026-09-21", "plan": "Silver PPO", "provider": "Riverbend Clinic", "amount_usd": 95.0, "status": "pending", "quarter": "2026-Q3"},
    {"claim_id": "C-87910", "member_id": "M-1002", "date": "2026-07-02", "plan": "Gold HMO", "provider": "Lakeview Pharmacy", "amount_usd": 42.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88104", "member_id": "M-1002", "date": "2026-08-11", "plan": "Gold HMO", "provider": "Summit Orthopedics", "amount_usd": 1280.0, "status": "denied", "quarter": "2026-Q3"},
    {"claim_id": "C-88233", "member_id": "M-1002", "date": "2026-09-03", "plan": "Gold HMO", "provider": "Lakeview Pharmacy", "amount_usd": 42.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88290", "member_id": "M-1002", "date": "2026-09-18", "plan": "Gold HMO", "provider": "Lakeview Pharmacy", "amount_usd": 42.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88017", "member_id": "M-1003", "date": "2026-07-25", "plan": "Silver PPO", "provider": "Bayside Dental", "amount_usd": 180.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88355", "member_id": "M-1003", "date": "2026-09-29", "plan": "Silver PPO", "provider": "Riverbend Clinic", "amount_usd": 310.0, "status": "pending", "quarter": "2026-Q3"},
    {"claim_id": "C-87977", "member_id": "M-1004", "date": "2026-07-08", "plan": "Bronze HDHP", "provider": "Northside Imaging", "amount_usd": 920.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88150", "member_id": "M-1004", "date": "2026-08-19", "plan": "Bronze HDHP", "provider": "Riverbend Clinic", "amount_usd": 120.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-88068", "member_id": "M-1005", "date": "2026-07-30", "plan": "Gold HMO", "provider": "Summit Orthopedics", "amount_usd": 2140.0, "status": "paid", "quarter": "2026-Q3"},
    {"claim_id": "C-86620", "member_id": "M-1005", "date": "2026-05-12", "plan": "Gold HMO", "provider": "Lakeview Pharmacy", "amount_usd": 38.0, "status": "paid", "quarter": "2026-Q2"},
    {"claim_id": "C-86701", "member_id": "M-1001", "date": "2026-05-20", "plan": "Silver PPO", "provider": "Bayside Dental", "amount_usd": 150.0, "status": "paid", "quarter": "2026-Q2"},
]  # fmt: skip

PII_COLUMNS = ("ssn", "dob", "email", "phone")

# --------------------------------------------------------------------------------------------
# Identities
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Persona:
    id: str
    name: str
    role: str
    title: str
    # Set only for members: the one member record this identity owns.
    member_id: str | None
    refund_limit_usd: float
    blurb: str


PERSONAS: dict[str, Persona] = {
    p.id: p
    for p in [
        Persona("member", "Maya Chen", "member", "Member (M-1001)", "M-1001", 0.0,
                "Can see her own profile and claims. Nobody else's."),
        Persona("support_rep", "Dev Alvarez", "support_rep", "Tier-1 support rep", None, 100.0,
                "Can look up any member with PII masked and issue refunds up to $100."),
        Persona("analyst", "Ana Lindqvist", "analyst", "Claims analyst", None, 0.0,
                "Can run aggregate reports. PII columns and individual records are off limits."),
        Persona("admin", "Sam Okoro", "admin", "Operations admin", None, 2500.0,
                "Can read full records, run reports and issue refunds up to $2,500."),
    ]
}  # fmt: skip


@dataclass(frozen=True)
class PolicyBundle:
    version: str
    note: str
    # The columns an analyst's report may read. None means "everything except the denylist",
    # which is how 2026.10.1 shipped; 2026.10.2 is an explicit allowlist.
    analyst_column_allowlist: tuple[str, ...] | None
    analyst_column_denylist: tuple[str, ...]


POLICIES: dict[str, PolicyBundle] = {
    "2026.10.1": PolicyBundle(
        "2026.10.1",
        "Column denylist written before `email` was added to members. Misses it.",
        None,
        ("ssn", "dob", "phone"),
    ),
    "2026.10.2": PolicyBundle(
        "2026.10.2",
        "Column allowlist: a new column is denied until someone grants it.",
        ("plan", "state", "date", "provider", "amount_usd", "status", "quarter"),
        (),
    ),
}  # fmt: skip
DEFAULT_POLICY = "2026.10.2"

# --------------------------------------------------------------------------------------------
# Scoped tokens
# --------------------------------------------------------------------------------------------

_SIGNING_KEY = os.environ.get("CORVID_TOKEN_KEY", "corvid-demo-signing-key").encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_token(persona_id: str, policy_version: str, ttl_s: int = 600) -> str:
    """Issue a short-lived token for one persona. This is the only place identity is decided."""
    persona = PERSONAS[persona_id]
    claims = {
        "sub": persona.id,
        "role": persona.role,
        "member_id": persona.member_id,
        "refund_limit_usd": persona.refund_limit_usd,
        "policy": policy_version,
        "exp": int(time.time()) + ttl_s,
    }
    body = _b64(json.dumps(claims, sort_keys=True).encode())
    sig = _b64(hmac.new(_SIGNING_KEY, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


class Forbidden(Exception):
    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule
        self.reason = reason


def verify_token(token: str) -> dict[str, Any]:
    body, _, sig = token.partition(".")
    expected = _b64(hmac.new(_SIGNING_KEY, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise Forbidden("token.signature", "token signature is invalid")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    if claims["exp"] < time.time():
        raise Forbidden("token.expired", "token has expired")
    return claims


def token_claims_preview(token: str) -> dict[str, Any]:
    """The decoded claims, for display. Never handed to the model."""
    claims = verify_token(token)
    return {k: v for k, v in claims.items() if k != "exp"}


# --------------------------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------------------------

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "get_member",
        "description": "Look up a member's profile by member_id.",
        "input_schema": {
            "type": "object",
            "properties": {"member_id": {"type": "string", "description": "e.g. M-1002"}},
            "required": ["member_id"],
        },
    },
    {
        "name": "list_claims",
        "description": "List a member's claims by member_id.",
        "input_schema": {
            "type": "object",
            "properties": {"member_id": {"type": "string"}},
            "required": ["member_id"],
        },
    },
    {
        "name": "issue_refund",
        "description": "Issue a refund to a member.",
        "input_schema": {
            "type": "object",
            "properties": {
                "member_id": {"type": "string"},
                "amount_usd": {"type": "number"},
                "reason": {"type": "string"},
            },
            "required": ["member_id", "amount_usd", "reason"],
        },
    },
    {
        "name": "run_report",
        "description": (
            "Run a read-only SQL query over the tables members(member_id, name, plan, ssn, dob, "
            "email, phone, state) and claims(claim_id, member_id, date, plan, provider, amount_usd, "
            "status, quarter). SQLite dialect."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"sql": {"type": "string"}},
            "required": ["sql"],
        },
    },
    {
        "name": "export_members",
        "description": "Export the full member table, including PII, as CSV.",
        "input_schema": {"type": "object", "properties": {}},
    },
]


@dataclass
class Decision:
    """One authorization decision, recorded whether the call was allowed or not."""

    tool: str
    input: dict[str, Any]
    allowed: bool
    rule: str
    reason: str
    result: Any = None


@dataclass
class ToolLayer:
    """Executes tools for exactly one token. Every call is authorized and recorded."""

    token: str
    refunds: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)

    def call(self, tool: str, args: dict[str, Any]) -> Decision:
        try:
            claims = verify_token(self.token)
            policy = POLICIES[claims["policy"]]
            handler = getattr(self, f"_tool_{tool}", None)
            if handler is None:
                raise Forbidden("tool.unknown", f"unknown tool {tool!r}")
            rule, result = handler(claims, policy, args)
            decision = Decision(tool, args, True, rule, "allowed", result)
        except Forbidden as exc:
            decision = Decision(
                tool,
                args,
                False,
                exc.rule,
                exc.reason,
                {"error": "forbidden", "reason": exc.reason},
            )
        except (KeyError, ValueError, TypeError) as exc:
            decision = Decision(tool, args, True, "tool.error", "allowed", {"error": str(exc)})
        self.decisions.append(decision)
        return decision

    # Each handler returns (rule that allowed it, result) or raises Forbidden(rule, reason).

    def _tool_get_member(
        self, claims: dict[str, Any], policy: PolicyBundle, args: dict[str, Any]
    ) -> tuple[str, Any]:
        member = _member(args["member_id"])
        role = claims["role"]
        if role == "member":
            if member["member_id"] != claims["member_id"]:
                raise Forbidden("row.own_records_only", "members can only read their own record")
            return "row.own_records_only", _masked(member, show_contact=True)
        if role == "support_rep":
            return "pii.masked_for_support", _masked(member, show_contact=False)
        if role == "admin":
            return "role.admin_full_read", dict(member)
        raise Forbidden(
            "role.no_record_access",
            f"role {role!r} cannot read individual member records",
        )

    def _tool_list_claims(
        self, claims: dict[str, Any], policy: PolicyBundle, args: dict[str, Any]
    ) -> tuple[str, Any]:
        member = _member(args["member_id"])
        role = claims["role"]
        if role == "member" and member["member_id"] != claims["member_id"]:
            raise Forbidden("row.own_records_only", "members can only read their own claims")
        if role == "analyst":
            raise Forbidden(
                "role.no_record_access", "analysts cannot read individual member claims"
            )
        rule = {
            "member": "row.own_records_only",
            "support_rep": "role.support_read",
            "admin": "role.admin_full_read",
        }[role]
        return rule, [c for c in CLAIMS if c["member_id"] == member["member_id"]]

    def _tool_issue_refund(
        self, claims: dict[str, Any], policy: PolicyBundle, args: dict[str, Any]
    ) -> tuple[str, Any]:
        member = _member(args["member_id"])
        amount = float(args["amount_usd"])
        if claims["role"] not in ("support_rep", "admin"):
            raise Forbidden("role.no_refunds", f"role {claims['role']!r} cannot issue refunds")
        if amount <= 0:
            raise ValueError("amount_usd must be positive")
        limit = float(claims["refund_limit_usd"])
        if amount > limit:
            raise Forbidden(
                "limit.refund_amount",
                f"${amount:,.2f} exceeds this identity's ${limit:,.2f} refund limit",
            )
        refund = {
            "refund_id": f"R-{len(self.refunds) + 5001}",
            "member_id": member["member_id"],
            "amount_usd": amount,
            "reason": args.get("reason", ""),
            "status": "issued",
        }
        self.refunds.append(refund)
        return "limit.refund_amount", refund

    def _tool_run_report(
        self, claims: dict[str, Any], policy: PolicyBundle, args: dict[str, Any]
    ) -> tuple[str, Any]:
        role = claims["role"]
        if role not in ("analyst", "admin"):
            raise Forbidden("role.no_reports", f"role {role!r} cannot run reports")
        sql = str(args["sql"])
        if role == "admin":
            return "role.admin_full_read", _run_sql(sql, allowed=None, denied=())
        return "column.analyst_policy", _run_sql(
            sql,
            allowed=policy.analyst_column_allowlist,
            denied=policy.analyst_column_denylist,
        )

    def _tool_export_members(
        self, claims: dict[str, Any], policy: PolicyBundle, args: dict[str, Any]
    ) -> tuple[str, Any]:
        if claims["role"] != "admin":
            raise Forbidden("role.no_export", f"role {claims['role']!r} cannot export member data")
        header = list(MEMBERS[0])
        rows = [",".join(header)] + [",".join(str(m[h]) for h in header) for m in MEMBERS]
        return "role.admin_full_read", {"csv": "\n".join(rows)}


def _member(member_id: Any) -> dict[str, Any]:
    for m in MEMBERS:
        if m["member_id"] == str(member_id).strip().upper():
            return m
    raise KeyError(f"no member {member_id!r}")


def _masked(member: dict[str, Any], *, show_contact: bool) -> dict[str, Any]:
    out = {k: member[k] for k in ("member_id", "name", "plan", "state")}
    out["ssn"] = "***-**-" + member["ssn"][-4:]
    if show_contact:
        out["email"] = member["email"]
        out["phone"] = member["phone"]
    return out


def _run_sql(sql: str, *, allowed: tuple[str, ...] | None, denied: tuple[str, ...]) -> Any:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE members (member_id, name, plan, ssn, dob, email, phone, state)")
    db.executemany(
        "INSERT INTO members VALUES (?,?,?,?,?,?,?,?)",
        [tuple(m.values()) for m in MEMBERS],
    )
    db.execute(
        "CREATE TABLE claims (claim_id, member_id, date, plan, provider, amount_usd, status, quarter)"
    )
    db.executemany(
        "INSERT INTO claims VALUES (?,?,?,?,?,?,?,?)",
        [tuple(c.values()) for c in CLAIMS],
    )
    blocked: list[str] = []

    # The engine asks this callback about every column the statement reads, after parsing and
    # before execution, so no rewrite of the SQL can reach a column the policy does not grant.
    def authorizer(
        action: int,
        arg1: str | None,
        arg2: str | None,
        _db: str | None,
        _trigger: str | None,
    ) -> int:
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION):
            return sqlite3.SQLITE_OK
        if action != sqlite3.SQLITE_READ:
            return sqlite3.SQLITE_DENY
        column = (arg2 or "").lower()
        if not column:
            return sqlite3.SQLITE_OK
        if allowed is not None and column not in allowed:
            blocked.append(f"{arg1}.{column}")
            return sqlite3.SQLITE_DENY
        if column in denied:
            blocked.append(f"{arg1}.{column}")
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    db.set_authorizer(authorizer)
    try:
        cur = db.execute(sql)
        cols = [d[0] for d in cur.description or []]
        rows = [dict(zip(cols, r)) for r in cur.fetchmany(50)]
    except sqlite3.DatabaseError as exc:
        if blocked:
            raise Forbidden(
                "column.analyst_policy",
                f"column policy denies {', '.join(sorted(set(blocked)))}",
            ) from exc
        raise ValueError(f"query failed: {exc}") from exc
    finally:
        db.close()
    return {"columns": cols, "rows": rows}
