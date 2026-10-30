#!/usr/bin/env python3
"""
WhiteHax GitHub Actions SARIF bridge.

Stable CI/SARIF handling plus a WhiteHax REST API adapter that:
1. authenticates (API key + email/password session),
2. starts a job against a configured profile (optionally creating an endpoint for TARGET_URL),
3. polls until the job completes,
4. fetches the report and maps failed tests into SARIF findings,
5. fetches recommendations and writes them to the GitHub job summary.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests


OUTPUT_FILE = Path("whitehax_results.sarif")
# GitHub code scanning rejects http(s) artifact URIs from a file:// checkout.
# Keep DAST target URLs in the finding message instead.
SARIF_ARTIFACT_URI = "whitehax_scans/whitehax_tests.py"
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "error": "error",
    "medium": "warning",
    "warning": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
    "none": "none",
}
DEFAULT_TIMEOUT = 30
DEFAULT_POLL_INTERVAL = 10
DEFAULT_POLL_TIMEOUT = 3600
DEFAULT_RECOMM_TIMEOUT = 120
# recomm_for selects the generator. "full" is the prompts-and-docs profile.
RECOMM_FOR_VALUES = ("full", "rto", "dos", "mcp", "reg", "llm")
RECOMM_LANGS = ("en", "fr", "es")


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def sarif_level(severity: Any) -> str:
    return SARIF_LEVELS.get(str(severity or "").strip().lower(), "warning")


def normalize_finding(raw: dict[str, Any]) -> dict[str, str]:
    """Map one WhiteHax API finding into the small internal shape below."""
    return {
        "id": str(raw.get("id") or raw.get("rule_id") or "WHX-GENERIC"),
        "title": str(raw.get("title") or raw.get("name") or "WhiteHax finding"),
        "description": str(raw.get("description") or raw.get("message") or ""),
        "severity": sarif_level(raw.get("severity")),
        "uri": str(raw.get("uri") or raw.get("path") or ""),
    }


def _api_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:1000]
    if isinstance(payload, dict):
        for key in ("message", "detail", "error"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
            if value not in (None, False, True):
                return str(value)
    return response.text[:1000]


def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Any:
    response = requests.request(
        method,
        url,
        headers=headers or {},
        data=data,
        timeout=timeout,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"{method} {url} failed ({response.status_code}): {_api_error_message(response)}"
        )
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"{method} {url} returned non-JSON body") from exc


class WhiteHaxClient:
    def __init__(self, base_url: str, api_key: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.email = email
        self.password = password
        self.session_key = ""

    def _headers(self, with_session: bool = True) -> dict[str, str]:
        headers = {"Authorization": self.api_key}
        if with_session:
            if not self.session_key:
                raise RuntimeError("Session key is not initialized")
            headers["X-Session-Key"] = self.session_key
        return headers

    def authenticate(self) -> str:
        payload = _request(
            "POST",
            f"{self.base_url}/api/auth/session/",
            headers=self._headers(with_session=False),
            data={"email": self.email, "password": self.password},
        )
        session_key = payload.get("session_key")
        if not session_key:
            raise RuntimeError("Authentication succeeded but no session_key was returned")
        self.session_key = str(session_key)
        print("[INFO] WhiteHax authentication successful")
        return self.session_key

    def create_endpoint(self, target_url: str) -> int:
        endpoint_name = os.environ.get(
            "WHITEHAX_ENDPOINT_NAME",
            f"ci-endpoint-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        )
        endpoint_type = os.environ.get("WHITEHAX_ENDPOINT_TYPE", "api_endpoint")
        endpoint_description = os.environ.get("WHITEHAX_ENDPOINT_DESCRIPTION", "Created by GitHub Actions WhiteHax DAST bridge")
        request_json = json.loads(os.environ.get("WHITEHAX_REQUEST_JSON", "{}"))
        response_json = json.loads(os.environ.get("WHITEHAX_RESPONSE_JSON", "{}"))

        payload = {
            "endpoint_name": endpoint_name,
            "endpoint_description": endpoint_description,
            "endpoint_type": endpoint_type,
            "endpoint_params": json.dumps(
                {
                    "url": target_url,
                    "selection": "json_parameters",
                }
            ),
            "json_parameters": json.dumps(
                {
                    "request": request_json,
                    "response": response_json,
                }
            ),
        }
        result = _request(
            "POST",
            f"{self.base_url}/api/endpoint-config/create/",
            headers=self._headers(),
            data=payload,
        )
        endpoint_id = (result.get("data") or {}).get("id") or result.get("id")
        if endpoint_id is None:
            raise RuntimeError(f"Endpoint create response missing id: {result}")
        print(f"[INFO] Created WhiteHax endpoint id={endpoint_id} for {target_url}")
        return int(endpoint_id)

    def create_profile(self, endpoint_config_id: int) -> int:
        profile_name = os.environ.get(
            "WHITEHAX_PROFILE_NAME",
            f"ci-profile-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        )
        profile_description = os.environ.get(
            "WHITEHAX_PROFILE_DESCRIPTION",
            "Created by GitHub Actions WhiteHax DAST bridge",
        )
        profile_type = os.environ.get("WHITEHAX_PROFILE_TYPE", "prompts_docs_llm")
        retry_attempts = env_int("WHITEHAX_RETRY_ATTEMPTS", 2)

        config_path = os.environ.get("WHITEHAX_PROFILE_CONFIG_PATH", "")
        if config_path:
            config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        else:
            config = {
                "profile_type": profile_type,
                "prompts_testing": {"enabled": True},
                "malicious_doc_uploads": {"enabled": False},
                "adv_multi_attacks": {"enabled": False, "sub": {}},
                "test_file_paths": {
                    "dos": [],
                    "llm": [],
                    "mcp": [],
                    "rto": [],
                    "docs": [],
                    "frame": [],
                    "prompts": [],
                    "rc_prompts": [],
                    "custom_decision_tree": [],
                },
            }

        payload = {
            "profile_name": profile_name,
            "profile_description": profile_description,
            "endpoint_config_id": str(endpoint_config_id),
            "profile_type": profile_type,
            "retry_attempts": str(retry_attempts),
            "config": json.dumps(config),
        }
        result = _request(
            "POST",
            f"{self.base_url}/api/profiles-config/create/",
            headers=self._headers(),
            data=payload,
        )
        profile_id = result.get("id")
        if profile_id is None:
            raise RuntimeError(f"Profile create response missing id: {result}")
        print(f"[INFO] Created WhiteHax profile id={profile_id}")
        return int(profile_id)

    def start_job(self, profile_id: int, report_name: str) -> str:
        result = _request(
            "POST",
            f"{self.base_url}/api/jobs/",
            headers=self._headers(),
            data={"profile_id": str(profile_id), "report_name": report_name},
        )
        job_id = result.get("job_id")
        if job_id is None:
            raise RuntimeError(f"Job create response missing job_id: {result}")
        print(f"[INFO] Started WhiteHax job id={job_id} for profile_id={profile_id}")
        return str(job_id)

    def wait_for_report_id(self, job_id: str) -> str:
        poll_interval = env_int("WHITEHAX_POLL_INTERVAL", DEFAULT_POLL_INTERVAL)
        poll_timeout = env_int("WHITEHAX_POLL_TIMEOUT", DEFAULT_POLL_TIMEOUT)
        deadline = time.time() + poll_timeout
        url = f"{self.base_url}/api/jobs/{job_id}/status/"

        while True:
            if time.time() > deadline:
                raise TimeoutError(
                    f"Timed out waiting for WhiteHax job {job_id} after {poll_timeout}s"
                )

            payload = _request("GET", url, headers=self._headers())
            if payload.get("error") is True:
                raise RuntimeError(payload.get("message") or f"Job status error for {job_id}")

            data = payload.get("data") or {}
            overall = data.get("overall") or {}
            status = str(overall.get("status") or "").lower()
            completion = data.get("completion_pct", 0)
            print(f"[INFO] Job {job_id} status={status or 'unknown'} completion={completion}%")

            if status == "completed":
                report_id = data.get("report_id")
                if report_id is None:
                    raise RuntimeError(f"Job {job_id} completed without report_id")
                return str(report_id)
            if status in {"failed", "error", "canceled", "cancelled"}:
                raise RuntimeError(overall.get("error_msg") or f"WhiteHax job {job_id} {status}")

            time.sleep(poll_interval)

    def get_report(self, report_id: str) -> dict[str, Any]:
        payload = _request(
            "GET",
            f"{self.base_url}/api/readiness-score/getReportById/{report_id}",
            headers=self._headers(),
        )
        if not isinstance(payload, dict):
            raise RuntimeError(f"Unexpected report payload type: {type(payload)}")
        print(f"[INFO] Fetched WhiteHax report id={report_id}")
        return payload

    def get_recommendations(self, report_id: str) -> Any:
        """GET /api/readiness-score/recommendations/.

        Query params:
        - recomm_for: full (prompts and docs), rto, dos, mcp, reg, llm
        - report_id: report to process
        - lang: en (default), fr, es
        - consolidation: false reads the result table; true reads consolidated_report
        """
        recomm_for = os.environ.get("WHITEHAX_RECOMM_FOR", "full").strip().lower() or "full"
        lang = os.environ.get("WHITEHAX_LANG", "en").strip().lower() or "en"
        consolidation = env_bool("WHITEHAX_CONSOLIDATION", default=False)
        timeout = env_int("WHITEHAX_RECOMM_TIMEOUT", DEFAULT_RECOMM_TIMEOUT)
        if recomm_for not in RECOMM_FOR_VALUES:
            print(
                f"[WARN] recomm_for={recomm_for!r} is not one of {', '.join(RECOMM_FOR_VALUES)}; "
                "full is the prompts-and-docs profile"
            )
        if lang not in RECOMM_LANGS:
            print(f"[WARN] lang={lang!r} is not one of {', '.join(RECOMM_LANGS)}; sending it anyway")
        query = urlencode(
            {
                "recomm_for": recomm_for,
                "report_id": report_id,
                "lang": lang,
                "consolidation": "true" if consolidation else "false",
            }
        )
        url = f"{self.base_url}/api/readiness-score/recommendations/?{query}"
        source = "consolidated_report" if consolidation else "result table"
        print(
            f"[INFO] Requesting recommendations report_id={report_id} "
            f"recomm_for={recomm_for} lang={lang} consolidation={str(consolidation).lower()} "
            f"source={source} timeout={timeout}s"
        )
        print(f"[INFO] GET {url}")
        started = time.perf_counter()
        payload = _request("GET", url, headers=self._headers(), timeout=timeout)
        elapsed = time.perf_counter() - started
        print(f"[INFO] Recommendations response received in {elapsed:.1f}s")
        return payload


def _md(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _label(key: Any) -> str:
    return str(key).replace("_", " ").strip().capitalize()


def _is_code_text(key: str, text: str) -> bool:
    lowered = key.lower()
    markers = ("code", "snippet", "pattern", "expression", "example", "regex")
    return any(marker in lowered for marker in markers) or "\n" in text or len(text) > 240


def _fence(text: str) -> list[str]:
    tick = "```"
    while tick in text:
        tick += "`"
    return ["", tick, text.rstrip("\n"), tick, ""]


def _render_block(value: Any, level: int = 3) -> list[str]:
    """Render a recommendation value without dropping nested text."""
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            key_text = str(key)
            if isinstance(item, str) and _is_code_text(key_text, item):
                lines.append(f"**{_label(key_text)}**")
                lines.extend(_fence(item))
                continue
            if isinstance(item, (dict, list)):
                lines.append(f"{'#' * min(level, 6)} {_label(key_text)}")
                lines.append("")
                lines.extend(_render_block(item, level + 1))
                continue
            lines.append(f"- **{_label(key_text)}:** {_md(item)}")
        if lines and lines[-1] != "":
            lines.append("")
        return lines

    if isinstance(value, list):
        lines = []
        for index, item in enumerate(value, start=1):
            if isinstance(item, dict) and {"action", "priority", "implementation"} & item.keys():
                lines.extend(_render_action(item, index))
                continue
            if isinstance(item, (dict, list)):
                lines.append(f"{'#' * min(level, 6)} Item {index}")
                lines.append("")
                lines.extend(_render_block(item, level + 1))
                continue
            lines.append(f"- {_md(item)}")
        if lines and lines[-1] != "":
            lines.append("")
        return lines

    if isinstance(value, str) and _is_code_text("", value):
        return _fence(value)
    return [f"{_md(value)}", ""]


def _render_action(action: dict[str, Any], index: int) -> list[str]:
    priority = _md(action.get("priority")) or "Unspecified"
    category = _md(action.get("category"))
    title = _md(action.get("action") or action.get("title")) or "Action"
    lines = [f"#### {index}. {title}", "", f"**{priority}**" + (f" · `{category}`" if category else ""), ""]
    if action.get("description"):
        lines.extend([_md(action.get("description")), ""])
    steps = action.get("implementation") or []
    if isinstance(steps, list) and steps:
        lines.extend(["**Implementation**", ""])
        for step in steps:
            if isinstance(step, (dict, list)):
                lines.extend(_render_block(step, 5))
            else:
                lines.append(f"- {_md(step)}")
        lines.append("")
    known = {"priority", "action", "title", "category", "description", "implementation"}
    extra = {key: value for key, value in action.items() if key not in known}
    if extra:
        lines.extend(_render_block(extra, 5))
    return lines


def _recommendation_view(payload: Any) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    data = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(data, dict):
        return {}, {}, []
    assessment = data.get("overall_assessment")
    summary = data.get("executive_summary")
    actions = data.get("prioritized_actions")
    return (
        assessment if isinstance(assessment, dict) else {},
        summary if isinstance(summary, dict) else {},
        actions if isinstance(actions, list) else [],
    )


def _posture_alert(posture: str) -> str:
    text = posture.strip().lower()
    if "critical" in text:
        return "CAUTION"
    if "high" in text or "urgent" in text:
        return "WARNING"
    if "medium" in text:
        return "IMPORTANT"
    return "NOTE"


def format_recommendations(payload: Any, report_id: str) -> str:
    documents = payload if isinstance(payload, list) else [payload]
    lines = ["## WhiteHax recommendations", "", f"Report `{report_id}`", ""]
    if not documents:
        lines.extend(["No recommendation payload was returned.", ""])
        return "\n".join(lines)

    for document_index, document in enumerate(documents, start=1):
        if not isinstance(document, dict):
            if len(documents) > 1:
                lines.extend([f"### Document {document_index}", ""])
            lines.extend(_render_block(document))
            continue

        assessment, summary, actions = _recommendation_view(document)
        posture = str(assessment.get("security_posture") or summary.get("security_status") or "")
        timeline = str(assessment.get("remediation_timeline") or summary.get("recommended_timeline") or "")
        if len(documents) > 1:
            lines.extend([f"### Document {document_index}", ""])
        if posture or timeline:
            alert = _posture_alert(posture or timeline)
            detail = " ".join(
                part
                for part in (
                    f"**{_md(posture)} posture.**" if posture else "",
                    _md(timeline) + "." if timeline else "",
                    f"Risk score {_md(assessment.get('overall_risk_score'))}."
                    if assessment.get("overall_risk_score") is not None
                    else "",
                    f"{_md(assessment.get('total_failed_tests'))} failed tests."
                    if assessment.get("total_failed_tests") is not None
                    else "",
                )
                if part
            )
            lines.extend([f"> [!{alert}]", f"> {detail}", ""])

        lines.extend(
            [
                "| Metric | Value |",
                "| --- | --- |",
                f"| Security posture | {_md(posture)} |",
                f"| Timeline | {_md(timeline)} |",
                f"| Failed tests | {_md(assessment.get('total_failed_tests'))} |",
                f"| Critical | {_md(assessment.get('critical_vulnerabilities'))} |",
                f"| Risk score | {_md(assessment.get('overall_risk_score'))} |",
                "",
            ]
        )

        findings = summary.get("key_findings") or []
        if isinstance(findings, list) and findings:
            lines.append("### Key findings")
            lines.append("")
            lines.extend(_render_block(findings, 4))

        covered = {"executive_summary", "overall_assessment", "prioritized_actions"}
        if actions:
            lines.extend(["### Prioritized actions", ""])
            for index, action in enumerate(actions, start=1):
                if isinstance(action, dict):
                    lines.extend(_render_action(action, index))
                else:
                    lines.extend(_render_block(action, 4))

        leftover_summary = {
            key: value
            for key, value in summary.items()
            if key not in {"security_status", "key_findings", "recommended_timeline"}
        }
        leftover_assessment = {
            key: value
            for key, value in assessment.items()
            if key
            not in {
                "security_posture",
                "remediation_timeline",
                "total_failed_tests",
                "critical_vulnerabilities",
                "overall_risk_score",
            }
        }
        if leftover_summary:
            lines.extend(["### Executive summary", ""])
            lines.extend(_render_block(leftover_summary))
        if leftover_assessment:
            lines.extend(["### Overall assessment", ""])
            lines.extend(_render_block(leftover_assessment))

        for key, value in document.items():
            if key in covered:
                continue
            lines.extend([f"### {_label(key)}", ""])
            lines.extend(_render_block(value, 4))

    return "\n".join(lines).rstrip() + "\n"


def publish_recommendations(client: WhiteHaxClient, report_id: str) -> None:
    print(f"[INFO] Report {report_id} is ready; loading recommendations")
    try:
        payload = client.get_recommendations(report_id)
    except Exception as exc:
        print(
            f"[WARN] Recommendations unavailable for report {report_id}: {exc}",
            file=sys.stderr,
        )
        traceback.print_exc()
        return

    if isinstance(payload, dict):
        print(f"[INFO] Recommendations payload keys: {', '.join(payload.keys()) or '(none)'}")
    elif isinstance(payload, list):
        print(f"[INFO] Recommendations payload is a list of {len(payload)} item(s)")
    else:
        print(f"[INFO] Recommendations payload type: {type(payload).__name__}")

    assessment, summary, actions = _recommendation_view(payload)
    posture = assessment.get("security_posture") or summary.get("security_status") or "unknown"
    timeline = assessment.get("remediation_timeline") or summary.get("recommended_timeline") or "unknown"
    print(
        f"[INFO] Recommendations summary posture={posture} timeline={timeline} "
        f"failed_tests={assessment.get('total_failed_tests', 'n/a')} "
        f"critical={assessment.get('critical_vulnerabilities', 'n/a')} "
        f"actions={len(actions)}"
    )
    for index, action in enumerate(actions, start=1):
        if not isinstance(action, dict):
            print(f"[INFO] Action {index}/{len(actions)}: {action}")
            continue
        print(
            f"[INFO] Action {index}/{len(actions)} "
            f"priority={action.get('priority') or 'n/a'} "
            f"category={action.get('category') or 'n/a'} "
            f"action={action.get('action') or 'n/a'}"
        )

    markdown = format_recommendations(payload, report_id)
    print("::group::WhiteHax recommendations")
    print(markdown)
    print("::endgroup::")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if not summary_path:
        print("[INFO] GITHUB_STEP_SUMMARY is unset; recommendations stay in the job log")
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(markdown + "\n")
    print(f"[INFO] Wrote recommendations to GitHub step summary ({summary_path})")


def _risk_to_severity(risk: Any, default: str = "medium") -> str:
    text = str(risk or "").strip().lower()
    if text in SARIF_LEVELS:
        return text
    if text in {"severe", "critical"}:
        return "critical"
    return default


def findings_from_report(report: dict[str, Any], target_url: str) -> list[dict[str, Any]]:
    score_json = report.get("score_json") or {}
    if isinstance(score_json, str):
        score_json = json.loads(score_json)

    findings: list[dict[str, Any]] = []
    quick_stats = score_json.get("quick_stats") or {}
    overall_risk = quick_stats.get("overall_risk_level") or "medium"
    total_failed = quick_stats.get("total_failed_tests") or 0
    overall_readiness = report.get("overall_readiness")
    if overall_readiness is None:
        overall_readiness = quick_stats.get("overall_readiness")

    findings.append(
        {
            "id": "WHX-SUMMARY",
            "title": "WhiteHax scan summary",
            "description": (
                f"Report '{report.get('report_name') or report.get('id')}' "
                f"readiness={overall_readiness}, failed_tests={total_failed}, "
                f"risk={overall_risk}"
            ),
            "severity": _risk_to_severity(overall_risk, "info"),
            "uri": target_url,
        }
    )

    data = score_json.get("data") or {}
    if isinstance(data, dict):
        for category, category_data in data.items():
            if not isinstance(category_data, dict):
                continue
            failed_tests = category_data.get("failed_tests") or {}
            if not isinstance(failed_tests, dict):
                continue
            for sub_category, items in failed_tests.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    response = item.get("response") or {}
                    if not isinstance(response, dict):
                        response = {}
                    reason = (
                        response.get("vuln_reason")
                        or response.get("vuln_verdict")
                        or item.get("details")
                        or "WhiteHax failed test"
                    )
                    risk = (
                        item.get("risk_level")
                        or response.get("risk_level")
                        or overall_risk
                        or "high"
                    )
                    test_id = item.get("test_id") or "unknown"
                    payload = item.get("payload")
                    description = str(reason)
                    if payload:
                        description = f"{description}\nPayload: {payload}"
                    findings.append(
                        {
                            "id": f"WHX-{category}-{sub_category}-{test_id}",
                            "title": f"{category}/{sub_category} failed test {test_id}",
                            "description": description[:4000],
                            "severity": _risk_to_severity(risk, "high"),
                            "uri": target_url,
                        }
                    )

    mcp = score_json.get("mcp_agent_simulation") or {}
    if isinstance(mcp, dict):
        for item in mcp.get("security_findings") or []:
            if not isinstance(item, dict):
                continue
            findings.append(
                {
                    "id": f"WHX-MCP-{item.get('test_id') or item.get('attack_type') or 'finding'}",
                    "title": item.get("attack_type") or "MCP security finding",
                    "description": str(
                        item.get("security_impact") or item.get("details") or "MCP finding"
                    )[:4000],
                    "severity": _risk_to_severity(item.get("risk_level"), "high"),
                    "uri": mcp.get("target_url") or target_url,
                }
            )

    dos = score_json.get("dos_simulation") or {}
    if isinstance(dos, dict):
        for item in dos.get("detailed_results") or []:
            if not isinstance(item, dict):
                continue
            if item.get("passed") is True:
                continue
            findings.append(
                {
                    "id": f"WHX-DOS-{item.get('test_id') or item.get('attack_type') or 'scenario'}",
                    "title": item.get("attack_type") or "DoS simulation failure",
                    "description": str(item.get("details") or "DoS scenario failed")[:4000],
                    "severity": _risk_to_severity(item.get("risk_level"), "high"),
                    "uri": target_url,
                }
            )

    # Keep summary-only runs useful even when every category passed.
    if len(findings) == 1 and int(float(total_failed or 0)) == 0:
        findings[0]["severity"] = "note"

    return findings


def run_whitehax_scan(whitehax_url: str, api_key: str, target_url: str) -> list[dict[str, Any]]:
    email = require_env("WHITEHAX_EMAIL") # "hbr@ironsdn.com"
    password = require_env("WHITEHAX_PASSWORD") # "hbr123"
    client = WhiteHaxClient(whitehax_url, api_key, email, password)
    client.authenticate()

    report_id = os.environ.get("WHITEHAX_REPORT_ID", "").strip()
    if report_id:
        print(f"[INFO] Using existing report id={report_id} (skip job start)")
        report = client.get_report(report_id)
    else:
        profile_id_raw = os.environ.get("WHITEHAX_PROFILE_ID", "").strip()
        create_resources = env_bool("WHITEHAX_CREATE_RESOURCES", default=not bool(profile_id_raw))

        if create_resources:
            endpoint_id = client.create_endpoint(target_url)
            profile_id = client.create_profile(endpoint_id)
        else:
            profile_id = int(profile_id_raw)
            print(f"[INFO] Reusing WhiteHax profile id={profile_id}")

        report_name = os.environ.get(
            "WHITEHAX_REPORT_NAME",
            f"github-actions-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        )
        job_id = client.start_job(profile_id, report_name)
        report_id = client.wait_for_report_id(job_id)
        print(f"[INFO] Job finished; report id={report_id}")
        report = client.get_report(report_id)

    publish_recommendations(client, report_id)
    return findings_from_report(report, target_url)


def build_sarif(
    findings: list[dict[str, Any]],
    target_url: str,
    execution_error: str | None = None,
) -> dict[str, Any]:
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "WhiteHax DAST",
                "informationUri": "https://whitehax.com",
                "rules": [],
            }
        },
        "results": [],
        "invocations": [
            {
                "executionSuccessful": execution_error is None,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    rules: dict[str, dict[str, Any]] = {}
    for raw in findings:
        finding = normalize_finding(raw)
        if finding["id"] not in rules:
            rules[finding["id"]] = {
                "id": finding["id"],
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["description"] or finding["title"]},
                "defaultConfiguration": {"level": finding["severity"]},
            }

        message = finding["description"] or finding["title"]
        endpoint = finding["uri"] or target_url
        if endpoint and endpoint not in message:
            message = f"{message}\nTarget: {endpoint}"

        run["results"].append(
            {
                "ruleId": finding["id"],
                "level": finding["severity"],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": SARIF_ARTIFACT_URI,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
            }
        )

    if execution_error:
        rules["WHX-SCAN-ERROR"] = {
            "id": "WHX-SCAN-ERROR",
            "name": "WhiteHax scan execution error",
            "shortDescription": {"text": "WhiteHax scan execution error"},
            "defaultConfiguration": {"level": "warning"},
        }
        error_message = execution_error[:4000]
        if target_url and target_url not in error_message:
            error_message = f"{error_message}\nTarget: {target_url}"
        run["results"].append(
            {
                "ruleId": "WHX-SCAN-ERROR",
                "level": "warning",
                "message": {"text": error_message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": SARIF_ARTIFACT_URI,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
            }
        )

    run["tool"]["driver"]["rules"] = list(rules.values())
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def write_sarif(payload: dict[str, Any]) -> None:
    OUTPUT_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[INFO] Wrote SARIF results to {OUTPUT_FILE}")


def main() -> int:
    target_url = os.environ.get("TARGET_URL", "")
    try:
        whitehax_url = require_env("WHITEHAX_URL") 
        api_key = require_env("WHITEHAX_API_KEY")

        print("[INFO] Starting WhiteHax DAST verification")
        print(f"[INFO] Target URL: {target_url}")
        findings = run_whitehax_scan(whitehax_url, api_key, target_url)
        write_sarif(build_sarif(findings, target_url))
        print(f"[INFO] Mapped {len(findings)} finding(s) into SARIF")
    except Exception as exc:
        print("[ERROR] WhiteHax scan failed:", exc, file=sys.stderr)
        traceback.print_exc()
        write_sarif(build_sarif([], target_url or "about:blank", str(exc)))
        if os.environ.get("WHITEHAX_FAIL_ON_ERROR", "false").lower() == "true":
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
