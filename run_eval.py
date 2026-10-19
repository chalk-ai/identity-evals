#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12,<3.14"
# dependencies = ["chalkcompute==2.13.5", "pyarrow"]
# ///
"""Run the negative-authorization evaluation: every persona against every task, per policy bundle.

    ./run_eval.py [--policy 2026.10.1 --policy 2026.10.2]

The task function runs the agent as the row's persona. The scorers never ask the model what
happened: they read the tool layer's recorded decisions, and check that values from records
the persona may not see never reached the model. Results land in results/<policy>.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import chalkcompute
from chalkcompute import EvaluationScorerResult, Image, Secret

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
MODULES = ["corvid.py", "agent.py", "cases.py", "scoring.py"]


def configure_chalk() -> None:
    """Resolve deployment routing settings using the SDK's ambient login."""
    from chalkcompute import ConnectClient

    client = ConnectClient()
    try:
        client._ensure_auth()
        # Only routing settings are needed by the deployed app; credentials stay in the SDK.
        os.environ["CHALK_API_SERVER"] = client._api_server
        os.environ["CHALK_ENVIRONMENT_ID"] = client._env_id
    finally:
        client.close()


# The decorators below deploy when this module is imported, so credentials must be in place
# first. Inside the function's container this module is imported again, not run, and skips it.
if __name__ == "__main__":
    configure_chalk()

IMAGE = Image.debian_slim("3.12").pip_install(["anthropic==1.13.0", "chalkcompute==2.13.5"])
# This module is imported again inside each function's container, where the image is never
# used and the source files are not beside it, so the files are attached only where they exist.
if all((HERE / m).exists() for m in MODULES):
    for _module in MODULES:
        IMAGE = IMAGE.add_local_file(str(HERE / _module), f"/opt/corvid/{_module}")


@chalkcompute.function(
    name="identity-agent-task",
    image=IMAGE,
    concurrency=8,
    env={
        "AGENT_MODEL": "anthropic/claude-haiku-4-5",
        "ROUTER_API_KEY": Secret.from_chalk_env("CHALK_ROUTER_API_KEY"),
    },
)
def identity_agent_task(persona: str, request: str, policy: str) -> str:
    """Run the agent once as `persona` under `policy`; return the whole trace as JSON."""
    import os
    import sys

    sys.path.insert(0, "/opt/corvid")
    import anthropic

    import agent

    api = os.environ.get("CHALK_API_SERVER", "https://api.chalk.ai").rstrip("/")
    client = anthropic.Anthropic(
        base_url=f"{api}/v1/router",
        api_key=os.environ["ROUTER_API_KEY"],
        default_headers={"X-Chalk-Env-Id": os.environ["CHALK_ENVIRONMENT_ID"]},
        timeout=60.0,
        max_retries=3,
    )
    cfg = agent.ModelConfig(client, os.environ["AGENT_MODEL"])
    return json.dumps(agent.run(persona, request, policy, cfg), default=str)


@chalkcompute.function(name="authorization-enforced", image=IMAGE)
def authorization_enforced(output: str, expected: str, target_tool: str) -> EvaluationScorerResult:
    """Deny rows pass only if the tool layer refused; allow rows only if the tool succeeded."""
    import sys

    sys.path.insert(0, "/opt/corvid")
    import scoring

    if not output:
        return EvaluationScorerResult(score=0.0, metadata={"verdict": "task produced no trace"})
    score, meta = scoring.authorization(json.loads(output), expected, target_tool)
    return EvaluationScorerResult(score=score, metadata=meta)


@chalkcompute.function(name="no-restricted-leak", image=IMAGE)
def no_restricted_leak(output: str, canaries: str) -> EvaluationScorerResult:
    """No value from a record this identity may not read appears in the answer or tool results."""
    import sys

    sys.path.insert(0, "/opt/corvid")
    import scoring

    if not output:
        return EvaluationScorerResult(score=0.0, metadata={"verdict": "task produced no trace"})
    score, meta = scoring.no_leak(json.loads(output), scoring.split_canaries(canaries))
    return EvaluationScorerResult(score=score, metadata=meta)


def _wait(run_id: str, timeout: float) -> chalkcompute.EvaluationRun:
    # A run advances when it is read, and finalizing inside that read can outlast one RPC's
    # deadline, so a failed poll is retried rather than treated as a failed run.
    deadline = time.monotonic() + timeout
    while True:
        try:
            run = chalkcompute.EvaluationRun.from_id(run_id)
            if run.is_terminal:
                return run
            print(f"  {run_id}: {run.status}", flush=True)
        except chalkcompute.EvaluationError as exc:
            print(f"  (poll retry: {exc})", flush=True)
        if time.monotonic() > deadline:
            raise TimeoutError(f"evaluation run {run_id} not finished after {timeout}s")
        time.sleep(15)


def _summarize(
    table_rows: list[dict],
    run: chalkcompute.EvaluationRun,
    evaluation_id: str,
    policy: str,
) -> dict:
    def scorer(row: dict, stem: str) -> tuple[float | None, dict]:
        value = next((row[k] for k in row if k.startswith(stem) and k.endswith("_value")), None)
        meta_raw = next(
            (row[k] for k in row if k.startswith(stem) and k.endswith("_metadata")),
            None,
        )
        if isinstance(value, dict):
            meta_raw = value.get("metadata", meta_raw)
            value = value.get("score")
        meta = json.loads(meta_raw) if isinstance(meta_raw, str) and meta_raw else (meta_raw or {})
        return value, meta

    out_rows = []
    for row in table_rows:
        trace = json.loads(row["output"]) if row.get("output") else {}
        auth, auth_meta = scorer(row, "authorization-enforced")
        leak, leak_meta = scorer(row, "no-restricted-leak")
        out_rows.append(
            {
                "case_id": row["case_id"],
                "persona": row["persona"],
                "task": row["task"],
                "expected": row["expected"],
                "authorization": {"score": auth, **auth_meta},
                "no_leak": {"score": leak, **leak_meta},
                "tools": [
                    {"tool": e["tool"], "input": e["input"], "allowed": e["allowed"], "rule": e["rule"], "reason": e["reason"]}
                    for e in trace.get("events", []) if e.get("type") == "tool"
                ],
                "answer": trace.get("answer", ""),
            }
        )  # fmt: skip
    out_rows.sort(key=lambda r: r["case_id"])
    passed = sum(
        1 for r in out_rows if r["authorization"]["score"] == 1 and r["no_leak"]["score"] == 1
    )
    return {
        "policy": policy,
        "evaluation_id": evaluation_id,
        "run_id": run.id,
        "status": str(run.status),
        "rows": out_rows,
        "passed": passed,
        "total": len(out_rows),
    }


def main() -> int:
    import cases

    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", action="append", default=None)
    # Re-read recorded runs instead of starting new ones: policy:evaluation_id:run_id.
    parser.add_argument("--summarize", action="append", default=None)
    args = parser.parse_args()
    policies = args.policy or ["2026.10.1", "2026.10.2"]

    runs: list[tuple[str, str, str]] = []
    for spec in args.summarize or []:
        policy, evaluation_id, run_id = spec.split(":")
        runs.append((policy, evaluation_id, run_id))
    if not runs:
        for function in (identity_agent_task, authorization_enforced, no_restricted_leak):
            function.wait_ready(timeout=900)

        client = chalkcompute.EvaluationClient()
        suite = next(
            (s for s in client.list_suites() if s.name == "identity-evals"), None
        ) or client.create_suite("identity-evals")
        for policy in policies:
            rows = cases.rows(policy)
            columns = {key: [r[key] for r in rows] for key in rows[0]}
            dataset = chalkcompute.DatasetClient().upload(
                f"identity-matrix-{policy.replace('.', '-')}", columns
            )
            evaluation = chalkcompute.EvaluationClient().create(
                f"negative-authorization policy {policy}",
                dataset=dataset,
                task=identity_agent_task,
                scorers=[authorization_enforced, no_restricted_leak],
                metadata={"policy": policy},
                suite_id=suite.id,
            )
            run = evaluation.run(metadata={"policy": policy})
            print(
                f"policy {policy}: evaluation {evaluation.id} run {run.id} ({len(rows)} rows)",
                flush=True,
            )
            runs.append((policy, evaluation.id, run.id))

    results_dir = HERE / "results"
    results_dir.mkdir(exist_ok=True)
    exit_code = 0
    for policy, evaluation_id, run_id in runs:
        run = _wait(run_id, 3600.0)
        print(f"policy {policy}: {run.status}", flush=True)
        if run.result_dataset is None:
            exit_code = 1
            continue
        table = chalkcompute.DatasetClient().read(run.result_dataset)
        print("  result columns:", table.column_names)
        summary = _summarize(table.to_pylist(), run, evaluation_id, policy)
        (results_dir / f"{policy}.json").write_text(json.dumps(summary, indent=2, default=str))
        print(f"  {summary['passed']}/{summary['total']} cases passed")
        for r in summary["rows"]:
            flag = (
                "ok " if r["authorization"]["score"] == 1 and r["no_leak"]["score"] == 1 else "FAIL"
            )
            print(f"  {flag} {r['case_id']:<28} expected={r['expected']:<5} "
                  f"auth={r['authorization'].get('verdict')} leak={r['no_leak'].get('verdict')}")  # fmt: skip
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
