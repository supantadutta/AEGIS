"""AEGIS dashboard — FastAPI control panel + server-rendered HTML.

This is a full operator console, not a read-only viewer. From the browser you
can: run investigations, manage the approval queue, configure provider API keys
and feature flags, edit every YAML config, enable/test threat-intel
integrations, run live IOC lookups, manage allow/block lists, and generate
detections & SIEM queries — all persisted via the runtime settings store with no
file editing required.

Run: ``uvicorn orchestrator.dashboard.app:app`` and open http://localhost:8000.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import yaml
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from orchestrator.core import settings
from orchestrator.core.approvals import ApprovalManager
from orchestrator.core.config import (
    CONFIG_FILES,
    load_config,
    runtime_flags,
    save_config,
)
from orchestrator.core.memory import Memory
from orchestrator.core.state import SessionState
from orchestrator.dashboard import service
from orchestrator.tools import intel_sources, threat_intel
from orchestrator.tools.detections import (
    PLATFORM_KEYS,
    available_use_cases,
    generate_query,
    generate_sigma,
)
from orchestrator.tools.reports import REPORT_TYPES, render_report

# Make dashboard-saved settings (keys, flags) live for this process.
settings.apply_to_environ()

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(["html"]),
)
_env.globals["mask"] = settings.mask

# Provider connection settings rendered on the Settings page.
PROVIDER_SETTINGS: list[dict[str, str]] = [
    {"env": "OPENAI_API_KEY", "label": "OpenAI API key", "kind": "secret"},
    {"env": "OPENAI_BASE_URL", "label": "OpenAI base URL (optional)", "kind": "url"},
    {"env": "ANTHROPIC_API_KEY", "label": "Anthropic API key", "kind": "secret"},
    {"env": "GEMINI_API_KEY", "label": "Google Gemini API key", "kind": "secret"},
    {"env": "OPENROUTER_API_KEY", "label": "OpenRouter API key", "kind": "secret"},
    {"env": "OLLAMA_BASE_URL", "label": "Ollama base URL", "kind": "url"},
]

FLAG_SETTINGS: list[dict[str, Any]] = [
    {"env": "ROUTER_MODE", "label": "Router mode", "kind": "choice", "choices": ["rules", "llm"]},
    {"env": "ORCH_ENABLE_PARALLEL", "label": "Parallelize independent steps", "kind": "bool"},
    {"env": "ALLOW_EXTERNAL_FOR_SENSITIVE", "label": "Allow external models on sensitive data", "kind": "bool"},
    {"env": "AEGIS_AUTO_LIVE_INTEL", "label": "Auto live threat-intel in pipeline", "kind": "bool"},
    {"env": "AEGIS_DB_PATH", "label": "SQLite database path", "kind": "text"},
]

NAV = [
    ("/", "Overview"),
    ("/investigate", "Investigate"),
    ("/sessions", "Sessions"),
    ("/detections", "Detections"),
    ("/intel", "Threat Intel"),
    ("/integrations", "Integrations"),
    ("/settings", "Settings"),
]

app = FastAPI(title="AEGIS Dashboard", version="0.2.0")


# --- helpers ----------------------------------------------------------------


def _render(template_name: str, request: Request, **ctx: Any) -> HTMLResponse:
    template = _env.get_template(template_name)
    ctx.setdefault("nav", NAV)
    ctx.setdefault("path", request.url.path)
    ctx.setdefault("msg", request.query_params.get("msg"))
    ctx.setdefault("err", request.query_params.get("err"))
    return HTMLResponse(template.render(**ctx))


def _redirect(url: str, *, msg: str | None = None, err: str | None = None) -> RedirectResponse:
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    if params:
        url = f"{url}?{urlencode(params)}"
    return RedirectResponse(url=url, status_code=303)


def _storage() -> service.SQLiteStorage:
    return service.storage()


def _load(session_id: str) -> SessionState:
    store = _storage()
    try:
        try:
            return store.load_session(session_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="session not found") from exc
    finally:
        store.close()


def _bool_form(value: str | None) -> str:
    return "true" if value in ("on", "true", "1", "yes") else ""


# --- overview & sessions ----------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Any:
    return _render("index.html", request, stats=service.overview_stats(),
                   providers=service.provider_status())


@app.get("/sessions", response_class=HTMLResponse)
def sessions_page(request: Request) -> Any:
    store = _storage()
    try:
        sessions = store.list_sessions()
    finally:
        store.close()
    return _render("sessions.html", request, sessions=sessions)


@app.get("/session/{session_id}", response_class=HTMLResponse)
def session_detail(request: Request, session_id: str) -> Any:
    session = _load(session_id)
    report = ""
    try:
        report = render_report(session, "analyst")
    except Exception:  # noqa: BLE001
        pass
    pending = [a for a in session.approval_log if a.status == "pending"]
    return _render("session.html", request, s=session, report=report,
                   pending=pending, report_types=REPORT_TYPES, known_models=service.model_ids())


# --- investigate ------------------------------------------------------------


@app.get("/investigate", response_class=HTMLResponse)
def investigate_form(request: Request) -> Any:
    return _render("investigate.html", request)


@app.post("/investigate")
def investigate_run(
    alert_text: str = Form(""),
    fmt: str = Form("auto"),
    sensitivity: str = Form("internal"),
    auto_approve: str = Form(""),
) -> Any:
    if not alert_text.strip():
        return _redirect("/investigate", err="Provide alert text or JSON to investigate.")
    try:
        session = service.run_investigation(
            alert_text, fmt=fmt, sensitivity=sensitivity,
            auto_approve=_bool_form(auto_approve) == "true")
    except Exception as exc:  # noqa: BLE001
        return _redirect("/investigate", err=f"Investigation failed: {exc}")
    return _redirect(f"/session/{session.session_id}", msg=f"Investigation {session.status}.")


@app.post("/session/{session_id}/resume")
def session_resume(session_id: str, model: str = Form(""), auto_approve: str = Form("")) -> Any:
    try:
        service.resume_session(session_id, model=model or None,
                               auto_approve=_bool_form(auto_approve) == "true")
    except Exception as exc:  # noqa: BLE001
        return _redirect(f"/session/{session_id}", err=f"Resume failed: {exc}")
    return _redirect(f"/session/{session_id}", msg="Resumed.")


@app.post("/session/{session_id}/approve")
def approve(session_id: str) -> Any:
    store = _storage()
    try:
        session = store.load_session(session_id)
        ApprovalManager().approve_all_pending(session, decided_by="dashboard")
        store.append_audit(session_id, "dashboard", "approval_granted", "via dashboard")
        store.save_session(session)
    finally:
        store.close()
    # Continue the run now that the gate is approved.
    try:
        service.resume_session(session_id, auto_approve=False)
    except Exception:  # noqa: BLE001
        pass
    return _redirect(f"/session/{session_id}", msg="Approved and resumed.")


@app.post("/session/{session_id}/feedback")
def feedback(
    session_id: str,
    classification_correct: str = Form(""),
    severity_correct: str = Form(""),
    action_useful: str = Form(""),
    note: str = Form(""),
) -> Any:
    store = _storage()
    try:
        session = store.load_session(session_id)
        Memory(store).record_feedback(
            session,
            classification_correct=_bool_form(classification_correct) == "true",
            severity_correct=_bool_form(severity_correct) == "true",
            action_useful=_bool_form(action_useful) == "true", note=note)
    finally:
        store.close()
    return _redirect(f"/session/{session_id}", msg="Feedback recorded.")


# --- detections & queries ---------------------------------------------------


@app.get("/detections", response_class=HTMLResponse)
def detections_page(request: Request) -> Any:
    return _render("detections.html", request, use_cases=available_use_cases(),
                   platforms=sorted(set(PLATFORM_KEYS)), result=None)


@app.post("/detections", response_class=HTMLResponse)
def detections_generate(request: Request, kind: str = Form("query"),
                        platform: str = Form("splunk"), use_case: str = Form("brute-force")) -> Any:
    result: dict[str, Any] = {"kind": kind, "platform": platform, "use_case": use_case}
    try:
        if kind == "sigma":
            rule = generate_sigma(use_case)
            result["title"] = f"Sigma / {use_case}"
            result["body"] = rule.logic
        else:
            gq = generate_query(platform, use_case)
            result["title"] = f"{platform} / {use_case}"
            result["body"] = gq.query
            result["notes"] = gq.notes
    except (KeyError, ValueError) as exc:
        result["error"] = str(exc)
    return _render("detections.html", request, use_cases=available_use_cases(),
                   platforms=sorted(set(PLATFORM_KEYS)), result=result)


# --- threat intel -----------------------------------------------------------


@app.get("/intel", response_class=HTMLResponse)
def intel_page(request: Request) -> Any:
    return _render("intel.html", request, results=None, observable="",
                   allowlist=threat_intel.list_entries("allow"),
                   blocklist=threat_intel.list_entries("block"),
                   auto_live=intel_sources.auto_live_enabled())


@app.post("/intel/lookup", response_class=HTMLResponse)
def intel_lookup(request: Request, observable: str = Form(""), obs_type: str = Form("")) -> Any:
    observable = observable.strip()
    results = []
    if observable:
        # Explicit human action: do a real lookup (local + every configured source).
        results = threat_intel.enrich(observable, obs_type, live=True)
    return _render("intel.html", request, results=results, observable=observable,
                   allowlist=threat_intel.list_entries("allow"),
                   blocklist=threat_intel.list_entries("block"),
                   auto_live=intel_sources.auto_live_enabled())


@app.post("/intel/list/add")
def intel_list_add(which: str = Form("block"), indicator: str = Form(""),
                   obs_type: str = Form(""), note: str = Form("")) -> Any:
    ok = threat_intel.add_entry(which, indicator, obs_type, note)
    msg = f"Added {indicator} to {which}list." if ok else None
    err = None if ok else f"{indicator!r} is empty or already present."
    return _redirect("/intel", msg=msg, err=err)


@app.post("/intel/list/remove")
def intel_list_remove(which: str = Form("block"), indicator: str = Form("")) -> Any:
    ok = threat_intel.remove_entry(which, indicator)
    return _redirect("/intel", msg=f"Removed {indicator}." if ok else None,
                     err=None if ok else f"{indicator!r} not found.")


# --- integrations -----------------------------------------------------------


@app.get("/integrations", response_class=HTMLResponse)
def integrations_page(request: Request) -> Any:
    return _render("integrations.html", request, sources=intel_sources.source_configs(),
                   auto_live=intel_sources.auto_live_enabled())


@app.post("/integrations/save")
def integrations_save(name: str = Form(...), api_key: str = Form(""),
                      base_url: str = Form(""), enabled: str = Form("")) -> Any:
    cfg = load_config("integrations")
    src = next((s for s in cfg.get("external_sources", []) if s.get("name") == name), None)
    if src is None:
        return _redirect("/integrations", err=f"Unknown source: {name}")
    # Persist the key/url to the settings store (only if a new value was typed).
    changes: dict[str, str] = {}
    if api_key and src.get("api_key_env"):
        changes[src["api_key_env"]] = api_key
    if base_url and src.get("base_url_env"):
        changes[src["base_url_env"]] = base_url
    if changes:
        settings.update(changes)
    # Persist the enabled toggle to integrations.yaml.
    src["enabled"] = _bool_form(enabled) == "true"
    save_config("integrations", cfg)
    return _redirect("/integrations", msg=f"Saved {name}.")


@app.post("/integrations/test", response_class=HTMLResponse)
def integrations_test(request: Request, name: str = Form(...)) -> Any:
    result = intel_sources.test_source(name)
    return _render("integrations.html", request, sources=intel_sources.source_configs(),
                   auto_live=intel_sources.auto_live_enabled(), test_name=name, test_result=result)


# --- settings ---------------------------------------------------------------


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> Any:
    provider_values = [
        {**p, "value": os.getenv(p["env"], ""), "is_set": settings.is_set(p["env"])}
        for p in PROVIDER_SETTINGS
    ]
    flag_values = [{**f, "value": os.getenv(f["env"], "")} for f in FLAG_SETTINGS]
    return _render("settings.html", request, providers=provider_values, flags=flag_values,
                   runtime=runtime_flags(), config_names=list(CONFIG_FILES))


@app.post("/settings/providers")
async def settings_providers(request: Request) -> Any:
    form = await request.form()
    changes = {p["env"]: str(form.get(p["env"], "")) for p in PROVIDER_SETTINGS if form.get(p["env"]) is not None}
    # Only overwrite when a non-empty value was typed (blank leaves it as-is);
    # use the explicit "clear" checkbox to remove a stored key.
    to_apply: dict[str, str] = {}
    for env, val in changes.items():
        clear = form.get(f"clear_{env}")
        if clear:
            to_apply[env] = ""
        elif val:
            to_apply[env] = val
    if to_apply:
        settings.update(to_apply)
    return _redirect("/settings", msg="Provider settings saved.")


@app.post("/settings/flags")
async def settings_flags(request: Request) -> Any:
    form = await request.form()
    changes: dict[str, str] = {}
    for f in FLAG_SETTINGS:
        env = f["env"]
        if f["kind"] == "bool":
            changes[env] = _bool_form(str(form.get(env, "")) or None)
        else:
            val = str(form.get(env, ""))
            if val:
                changes[env] = val
    settings.update(changes)
    return _redirect("/settings", msg="Feature flags saved.")


@app.get("/settings/config/{name}", response_class=HTMLResponse)
def config_editor(request: Request, name: str) -> Any:
    if name not in CONFIG_FILES:
        raise HTTPException(status_code=404, detail="unknown config")
    raw = yaml.safe_dump(load_config(name), sort_keys=False, allow_unicode=True)
    return _render("config_edit.html", request, name=name, raw=raw,
                   config_names=list(CONFIG_FILES))


@app.post("/settings/config/{name}")
def config_save(name: str, content: str = Form(...)) -> Any:
    if name not in CONFIG_FILES:
        raise HTTPException(status_code=404, detail="unknown config")
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("top-level YAML must be a mapping")
    except (yaml.YAMLError, ValueError) as exc:
        return _redirect(f"/settings/config/{name}", err=f"Invalid YAML: {exc}")
    save_config(name, data)
    return _redirect(f"/settings/config/{name}", msg=f"Saved {name}.yaml")


# --- JSON API ---------------------------------------------------------------


@app.get("/healthz")
def healthz() -> Any:
    return {"status": "ok", "version": app.version}


@app.get("/api/sessions")
def api_sessions() -> Any:
    store = _storage()
    try:
        return store.list_sessions()
    finally:
        store.close()


@app.get("/api/session/{session_id}")
def api_session(session_id: str) -> Any:
    return JSONResponse(content=_load(session_id).model_dump(mode="json"))


@app.get("/api/session/{session_id}/report")
def api_report(session_id: str, type: str = "analyst") -> Any:
    session = _load(session_id)
    try:
        return {"type": type, "body": render_report(session, type)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/session/{session_id}/checkpoints")
def api_checkpoints(session_id: str) -> Any:
    store = _storage()
    try:
        return store.list_checkpoints(session_id)
    finally:
        store.close()


@app.get("/api/providers")
def api_providers() -> Any:
    return service.provider_status()


@app.get("/api/integrations")
def api_integrations() -> Any:
    return intel_sources.source_configs()
