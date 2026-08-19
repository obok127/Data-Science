#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Public-safe browser measurement collector.

Inspects public URLs, captures the first supported analytics page-view request,
extracts generalized measurement fields, and writes a resumable CSV checkpoint.

No production domains, credentials, internal URLs, proprietary business rules,
or real company-specific variable names are included.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qs, unquote, urlsplit

import pandas as pd
import requests

try:
    from playwright.async_api import Browser, BrowserContext, Page, Request, async_playwright
except ImportError as exc:
    raise SystemExit(
        "Playwright is required.\n"
        f'Install with:\n  "{sys.executable}" -m pip install pandas requests playwright\n'
        f'  "{sys.executable}" -m playwright install chromium'
    ) from exc

INSPECTION_VERSION = "public_measurement_collector_v1"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)

APPMEASUREMENT_FIELD_PARAMS = {
    "field_a": "c1",
    "field_b": "v1",
    "page_name": "pageName",
}

WEBSDK_FIELD_PATHS = {
    "field_a": [
        (("data", "__adobe", "analytics", "prop1"), "data.__adobe.analytics.prop1"),
        (("data", "__adobe", "analytics", "c1"), "data.__adobe.analytics.c1"),
        (("xdm", "_experience", "analytics", "customDimensions", "props", "prop1"), "xdm...props.prop1"),
    ],
    "field_b": [
        (("data", "__adobe", "analytics", "eVar1"), "data.__adobe.analytics.eVar1"),
        (("data", "__adobe", "analytics", "v1"), "data.__adobe.analytics.v1"),
        (("xdm", "_experience", "analytics", "customDimensions", "eVars", "eVar1"), "xdm...eVars.eVar1"),
    ],
}

RESULT_COLUMNS = [
    "normalized_url", "url_status", "http_precheck_status", "http_browser_status",
    "final_url", "redirected", "check_note", "cookie_consent_clicked",
    "first_pv_captured", "first_pv_capture_type", "first_pv_request_method",
    "current_field_a", "current_field_b", "current_field_a_source", "current_field_b_source",
    "current_page_name", "analytics_candidate_count", "pageview_hit_count",
    "candidate_event_types", "candidate_page_names", "candidate_field_a_values", "candidate_field_b_values",
    "analytics_capture_note", "current_document_title", "inspection_error", "checked_at", "inspection_version",
]

SOFT_404_MARKERS = [
    "page not found", "404 not found", "the page you requested cannot be found",
    "seite nicht gefunden", "page introuvable", "pagina niet gevonden",
    "página no encontrada", "pagina non trovata", "página não encontrada",
    "페이지를 찾을 수 없습니다", "ページが見つかりません", "halaman tidak ditemukan",
]
ERROR_PATH_MARKERS = ["/404", "/error/", "/page-not-found", "/not-found"]
CONSENT_SELECTORS = [
    "#onetrust-accept-btn-handler",
    "button:has-text('Accept All')",
    "button:has-text('Accept all')",
    "button:has-text('Agree')",
]
ANALYTICS_HOST_MARKERS = ("omtrdc.net", "2o7.net", "adobedc.net")
ANALYTICS_PATH_MARKERS = ("/b/ss/", "/interact", "/collect", "/ee/v1/", "/edge/v1/")

@dataclass
class PrecheckResult:
    status_code: int | None = None
    final_url: str | None = None
    note: str = "not run"

def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def clean_scalar(value: Any) -> Any:
    if value is None:
        return pd.NA
    try:
        if pd.isna(value):
            return pd.NA
    except Exception:
        pass
    text = str(value).strip()
    return text if text else pd.NA

def join_unique(values: Iterable[Any], limit: int = 8000) -> Any:
    output: list[str] = []
    current_length = 0
    for value in values:
        value = clean_scalar(value)
        if pd.isna(value):
            continue
        text = str(value)
        if text in output:
            continue
        extra = len(text) + (3 if output else 0)
        if current_length + extra > limit:
            output.append("...[truncated]")
            break
        output.append(text)
        current_length += extra
    return " | ".join(output) if output else pd.NA

def is_missing(value: Any) -> bool:
    value = clean_scalar(value)
    if pd.isna(value):
        return True
    return str(value).strip().lower() in {"", "undefined", "null", "none", "not set"}

def is_malformed_url(url: Any) -> tuple[bool, str]:
    if url is None or pd.isna(url):
        return True, "missing URL"
    text = str(url).strip()
    if not text:
        return True, "blank URL"
    if re.search(r"[\r\n\t]", text):
        return True, "control character in URL"
    if " " in text:
        return True, "raw space in URL"
    try:
        parts = urlsplit(text)
    except Exception as exc:
        return True, f"urlsplit error: {exc}"
    if parts.scheme.lower() not in {"http", "https"}:
        return True, "invalid or missing scheme"
    if not parts.netloc or not parts.hostname:
        return True, "missing or invalid host"
    decoded_path = unquote(parts.path)
    if re.search(r"https?://", decoded_path, flags=re.IGNORECASE):
        return True, "embedded URL inside path"
    if re.search(r"\{\{|\}\}|[<>|\\]", decoded_path):
        return True, "template or invalid path character"
    if re.search(r"%(?![0-9A-Fa-f]{2})", text):
        return True, "invalid percent encoding"
    return False, ""

def http_precheck(url: str, timeout_seconds: int) -> PrecheckResult:
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    try:
        response = requests.get(url, headers=headers, timeout=timeout_seconds, allow_redirects=True, stream=True)
        status = int(response.status_code)
        final_url = str(response.url)
        response.close()
        return PrecheckResult(status, final_url, f"requests status {status}")
    except requests.RequestException as exc:
        return PrecheckResult(None, None, f"requests failed: {type(exc).__name__}")

def detect_analytics_capture_type(url: str) -> str | None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path.lower()
    if "/b/ss/" in path:
        return "AppMeasurement"
    is_adobe_host = any(marker in host for marker in ANALYTICS_HOST_MARKERS)
    is_edge_path = any(marker in path for marker in ANALYTICS_PATH_MARKERS[1:])
    if is_adobe_host and is_edge_path:
        return "WebSDK"
    if is_edge_path and any(token in host for token in ("adobe", "edge", "collect", "metrics")):
        return "WebSDK"
    return None

def parse_form_payload(text: str | None) -> dict[str, list[str]]:
    if not text:
        return {}
    try:
        return parse_qs(text, keep_blank_values=True)
    except Exception:
        return {}

def request_json_body(request: Request) -> Any:
    try:
        return request.post_data_json
    except Exception:
        pass
    text = request.post_data
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None

def nested_get(mapping: Any, path: Sequence[str]) -> Any:
    current = mapping
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current

def unwrap_payload_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        for key in ("value", "values", "id"):
            if key in value and not is_missing(value.get(key)):
                nested = value.get(key)
                if isinstance(nested, list):
                    return " | ".join(str(item) for item in nested if not is_missing(item))
                return nested
    return value

def first_known_path(root: Any, paths: Sequence[tuple[Sequence[str], str]]) -> tuple[Any, str | None]:
    for path, label in paths:
        value = unwrap_payload_value(nested_get(root, path))
        if not is_missing(value):
            return value, label
    return None, None

def recursive_key_fallback(root: Any, keys: set[str], prefix: str = "") -> tuple[Any, str | None]:
    if isinstance(root, Mapping):
        for key, value in root.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if str(key) in keys:
                unwrapped = unwrap_payload_value(value)
                if not is_missing(unwrapped):
                    return unwrapped, path
            found, found_path = recursive_key_fallback(value, keys, path)
            if not is_missing(found):
                return found, found_path
    elif isinstance(root, list):
        for index, item in enumerate(root):
            path = f"{prefix}[{index}]"
            found, found_path = recursive_key_fallback(item, keys, path)
            if not is_missing(found):
                return found, found_path
    return None, None

def parse_appmeasurement_request(request: Request) -> list[dict[str, Any]]:
    params: dict[str, list[str]] = {}
    try:
        query = parse_qs(urlsplit(request.url).query, keep_blank_values=True)
        for key, values in query.items():
            params.setdefault(key, []).extend(values)
    except Exception:
        pass
    body_json = request_json_body(request)
    if isinstance(body_json, Mapping):
        for key, value in body_json.items():
            if isinstance(value, list):
                params.setdefault(str(key), []).extend(str(v) for v in value)
            else:
                params.setdefault(str(key), []).append(str(value))
    else:
        for key, values in parse_form_payload(request.post_data).items():
            params.setdefault(key, []).extend(values)
    def first(key: str) -> str | None:
        values = params.get(key, [])
        return values[0] if values else None
    def resolved(key: str, depth: int = 0) -> str | None:
        value = first(key)
        if value is None or depth > 5:
            return value
        if value.startswith("D="):
            reference = value[2:]
            if reference in params:
                return resolved(reference, depth + 1)
        return value
    pe = first("pe")
    is_page_view = is_missing(pe)
    return [{
        "capture_type": "AppMeasurement",
        "is_page_view": is_page_view,
        "page_view_reason": "AppMeasurement pe missing" if is_page_view else None,
        "field_a": resolved(APPMEASUREMENT_FIELD_PARAMS["field_a"]),
        "field_b": resolved(APPMEASUREMENT_FIELD_PARAMS["field_b"]),
        "field_a_source": f"AppMeasurement {APPMEASUREMENT_FIELD_PARAMS['field_a']}",
        "field_b_source": f"AppMeasurement {APPMEASUREMENT_FIELD_PARAMS['field_b']}",
        "page_name": resolved(APPMEASUREMENT_FIELD_PARAMS["page_name"]),
        "event_type": None,
        "request_method": request.method,
    }]

def iter_websdk_events(body: Any) -> list[Mapping[str, Any]]:
    if isinstance(body, Mapping):
        events = body.get("events")
        if isinstance(events, list):
            return [event for event in events if isinstance(event, Mapping)]
        return [body]
    if isinstance(body, list):
        return [event for event in body if isinstance(event, Mapping)]
    return []

def parse_websdk_request(request: Request) -> list[dict[str, Any]]:
    body = request_json_body(request)
    output: list[dict[str, Any]] = []
    for event in iter_websdk_events(body):
        xdm = event.get("xdm") if isinstance(event.get("xdm"), Mapping) else {}
        data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
        analytics_data = nested_get(data, ["__adobe", "analytics"])
        if not isinstance(analytics_data, Mapping):
            analytics_data = {}
        web_page_details = nested_get(xdm, ["web", "webPageDetails"])
        if not isinstance(web_page_details, Mapping):
            web_page_details = {}
        field_a, field_a_source = first_known_path(event, WEBSDK_FIELD_PATHS["field_a"])
        field_b, field_b_source = first_known_path(event, WEBSDK_FIELD_PATHS["field_b"])
        if is_missing(field_a):
            field_a, field_a_source = recursive_key_fallback({"data": data, "xdm": xdm}, {"prop1", "c1"})
        if is_missing(field_b):
            field_b, field_b_source = recursive_key_fallback({"data": data, "xdm": xdm}, {"eVar1", "v1"})
        page_views = web_page_details.get("pageViews")
        page_view_value = page_views.get("value") if isinstance(page_views, Mapping) else page_views
        event_type = xdm.get("eventType") if isinstance(xdm, Mapping) and not is_missing(xdm.get("eventType")) else event.get("eventType")
        analytics_page_name = clean_scalar(analytics_data.get("pageName"))
        xdm_page_name = clean_scalar(web_page_details.get("name"))
        page_name = analytics_page_name if not pd.isna(analytics_page_name) else xdm_page_name
        link_type = clean_scalar(analytics_data.get("linkType"))
        link_name = clean_scalar(analytics_data.get("linkName"))
        has_link_signal = not is_missing(link_type) or not is_missing(link_name)
        event_type_text = "" if is_missing(event_type) else str(event_type).strip().lower()
        explicit_pageview_event = event_type_text == "web.webpagedetails.pageviews" or event_type_text.endswith(".pageviews") or event_type_text.endswith(".pageview")
        numeric_page_view = False
        if isinstance(page_view_value, (int, float)):
            numeric_page_view = page_view_value > 0
        elif isinstance(page_view_value, str):
            try:
                numeric_page_view = float(page_view_value.strip()) > 0
            except (TypeError, ValueError):
                numeric_page_view = False
        page_name_without_link = (not is_missing(page_name) and not has_link_signal and (not event_type_text or "webpagedetails" in event_type_text or "pageview" in event_type_text))
        if explicit_pageview_event:
            page_view_reason = "eventType pageViews"
        elif numeric_page_view:
            page_view_reason = "webPageDetails.pageViews > 0"
        elif page_name_without_link:
            page_view_reason = "pageName without link signal"
        else:
            page_view_reason = None
        output.append({
            "capture_type": "WebSDK",
            "is_page_view": page_view_reason is not None,
            "page_view_reason": page_view_reason,
            "field_a": field_a,
            "field_b": field_b,
            "field_a_source": field_a_source,
            "field_b_source": field_b_source,
            "page_name": page_name,
            "event_type": event_type,
            "request_method": request.method,
        })
    return output

def parse_analytics_request(request: Request) -> list[dict[str, Any]]:
    capture_type = detect_analytics_capture_type(request.url)
    if capture_type == "AppMeasurement":
        return parse_appmeasurement_request(request)
    if capture_type == "WebSDK":
        return parse_websdk_request(request)
    return []

async def click_cookie_consent(page: Page, wait_ms: int) -> bool:
    if wait_ms > 0:
        await page.wait_for_timeout(wait_ms)
    for selector in CONSENT_SELECTORS:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=800):
                await locator.click(timeout=2_000)
                await page.wait_for_timeout(800)
                return True
        except Exception:
            continue
    return False

async def inspect_with_browser(context: BrowserContext, url: str, *, precheck: PrecheckResult, navigation_timeout_ms: int, page_consent_wait_ms: int, pv_wait_ms: int) -> dict[str, Any]:
    page = await context.new_page()
    state: dict[str, Any] = {"hits": [], "first_pv": None, "event": asyncio.Event()}
    def reset_capture_state() -> None:
        state["hits"] = []
        state["first_pv"] = None
        state["event"] = asyncio.Event()
    def capture_request(request: Request) -> None:
        try:
            hits = parse_analytics_request(request)
        except Exception:
            return
        for hit in hits:
            state["hits"].append(hit)
            if hit.get("is_page_view") and state["first_pv"] is None:
                state["first_pv"] = hit
                state["event"].set()
    page.on("request", capture_request)
    browser_status: int | None = None
    final_url: str | None = None
    consent_clicked = False
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=navigation_timeout_ms)
        browser_status = int(response.status) if response is not None else None
        consent_clicked = await click_cookie_consent(page, page_consent_wait_ms)
        if consent_clicked:
            reset_capture_state()
            response = await page.reload(wait_until="domcontentloaded", timeout=navigation_timeout_ms)
            browser_status = int(response.status) if response is not None else browser_status
        if state["first_pv"] is None:
            try:
                await asyncio.wait_for(state["event"].wait(), timeout=max(pv_wait_ms, 0) / 1000)
            except asyncio.TimeoutError:
                pass
        final_url = page.url
        try:
            title_original = await page.title()
            title_text = title_original.lower()
        except Exception:
            title_original = ""
            title_text = ""
        try:
            body_text = (await page.locator("body").inner_text(timeout=5_000)).lower()[:250_000]
        except Exception:
            body_text = ""
        final_path = urlsplit(final_url or url).path.lower()
        soft_404 = any(marker in final_path for marker in ERROR_PATH_MARKERS) or any(marker in f"{title_text} {body_text}" for marker in SOFT_404_MARKERS)
        if browser_status in {404, 410}:
            url_status, note = "404", "browser hard 404/410"
        elif soft_404:
            url_status, note = "404", "soft 404 detected"
        elif browser_status is not None and 200 <= browser_status < 400:
            url_status, note = "Live", "live page"
        elif browser_status is not None and browser_status >= 400:
            url_status, note = "Review", f"browser status {browser_status}; manual review required"
        else:
            url_status, note = "Review", "main document response unavailable"
        first_pv = state["first_pv"]
        pageview_hits = [hit for hit in state["hits"] if hit.get("is_page_view")]
        if first_pv:
            current_field_a = clean_scalar(first_pv.get("field_a"))
            current_field_b = clean_scalar(first_pv.get("field_b"))
            current_field_a_source = clean_scalar(first_pv.get("field_a_source"))
            current_field_b_source = clean_scalar(first_pv.get("field_b_source"))
            current_page_name = clean_scalar(first_pv.get("page_name"))
            first_pv_capture_type = clean_scalar(first_pv.get("capture_type"))
            first_pv_method = clean_scalar(first_pv.get("request_method"))
            capture_note = "initial page-view Analytics request captured"
        elif state["hits"]:
            current_field_a = current_field_b = current_field_a_source = current_field_b_source = current_page_name = first_pv_capture_type = first_pv_method = pd.NA
            capture_note = "Analytics request captured, but initial page-view was not identified"
        else:
            current_field_a = current_field_b = current_field_a_source = current_field_b_source = current_page_name = first_pv_capture_type = first_pv_method = pd.NA
            capture_note = "no supported Analytics request captured"
        return {
            "normalized_url": url, "url_status": url_status, "http_precheck_status": precheck.status_code, "http_browser_status": browser_status,
            "final_url": clean_scalar(final_url), "redirected": bool(final_url and final_url.rstrip("/") != url.rstrip("/")),
            "check_note": note, "cookie_consent_clicked": consent_clicked, "first_pv_captured": bool(first_pv),
            "first_pv_capture_type": first_pv_capture_type, "first_pv_request_method": first_pv_method,
            "current_field_a": current_field_a, "current_field_b": current_field_b,
            "current_field_a_source": current_field_a_source, "current_field_b_source": current_field_b_source,
            "current_page_name": current_page_name, "analytics_candidate_count": len(state["hits"]), "pageview_hit_count": len(pageview_hits),
            "candidate_event_types": join_unique(hit.get("event_type") for hit in state["hits"]),
            "candidate_page_names": join_unique(hit.get("page_name") for hit in state["hits"]),
            "candidate_field_a_values": join_unique(hit.get("field_a") for hit in state["hits"]),
            "candidate_field_b_values": join_unique(hit.get("field_b") for hit in state["hits"]),
            "analytics_capture_note": capture_note, "current_document_title": clean_scalar(title_original),
            "inspection_error": pd.NA, "checked_at": now_text(), "inspection_version": INSPECTION_VERSION,
        }
    except Exception as exc:
        row = {column: pd.NA for column in RESULT_COLUMNS}
        row.update({
            "normalized_url": url, "url_status": "Review", "http_precheck_status": precheck.status_code,
            "http_browser_status": browser_status, "final_url": clean_scalar(final_url or getattr(page, "url", None)),
            "redirected": False, "check_note": "browser inspection failed", "cookie_consent_clicked": consent_clicked,
            "first_pv_captured": bool(state["first_pv"]), "analytics_candidate_count": len(state["hits"]),
            "pageview_hit_count": len([hit for hit in state["hits"] if hit.get("is_page_view")]),
            "analytics_capture_note": "capture incomplete because browser inspection failed",
            "inspection_error": f"{type(exc).__name__}: {exc}", "checked_at": now_text(), "inspection_version": INSPECTION_VERSION,
        })
        return row
    finally:
        await page.close()

def malformed_result(url: str, note: str) -> dict[str, Any]:
    row = {column: pd.NA for column in RESULT_COLUMNS}
    row.update({
        "normalized_url": url, "url_status": "Malformed", "redirected": False, "check_note": note,
        "cookie_consent_clicked": False, "first_pv_captured": False, "analytics_candidate_count": 0,
        "pageview_hit_count": 0, "analytics_capture_note": "browser not opened: malformed URL",
        "checked_at": now_text(), "inspection_version": INSPECTION_VERSION,
    })
    return row

def load_existing(output_path: Path, force: bool) -> dict[str, dict[str, Any]]:
    if force or not output_path.exists():
        return {}
    try:
        existing_df = pd.read_csv(output_path, encoding="utf-8-sig")
    except Exception:
        return {}
    required = {"normalized_url", "inspection_version", "url_status"}
    if not required.issubset(existing_df.columns):
        return {}
    reusable = existing_df[existing_df["inspection_version"].eq(INSPECTION_VERSION) & existing_df["url_status"].notna()].copy()
    return {str(row["normalized_url"]): row.to_dict() for _, row in reusable.iterrows()}

def save_results(result_map: dict[str, dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(result_map.values())
    for col in RESULT_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA
    df = df[RESULT_COLUMNS].sort_values("normalized_url").reset_index(drop=True)
    temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    df.to_csv(temp_path, index=False, encoding="utf-8-sig")
    temp_path.replace(output_path)

async def run_optional_precheck_batch(urls: list[str], *, enabled: bool, timeout_seconds: int, concurrency: int) -> dict[str, PrecheckResult]:
    if not enabled:
        return {url: PrecheckResult() for url in urls}
    semaphore = asyncio.Semaphore(concurrency)
    async def guarded(url: str) -> tuple[str, PrecheckResult]:
        async with semaphore:
            result = await asyncio.to_thread(http_precheck, url, timeout_seconds)
            return url, result
    return dict(await asyncio.gather(*(guarded(url) for url in urls)))

async def run_browser_batch(context: BrowserContext, jobs: list[tuple[str, PrecheckResult]], *, concurrency: int, navigation_timeout_ms: int, page_consent_wait_ms: int, pv_wait_ms: int) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)
    async def guarded(job: tuple[str, PrecheckResult]) -> dict[str, Any]:
        url, precheck = job
        async with semaphore:
            return await inspect_with_browser(context, url, precheck=precheck, navigation_timeout_ms=navigation_timeout_ms, page_consent_wait_ms=page_consent_wait_ms, pv_wait_ms=pv_wait_ms)
    return await asyncio.gather(*(guarded(job) for job in jobs))

async def async_main(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path.resolve()}")
    input_df = pd.read_csv(input_path, encoding="utf-8-sig")
    if "normalized_url" not in input_df.columns:
        raise ValueError("Input CSV must contain a normalized_url column.")
    urls = input_df["normalized_url"].dropna().astype(str).str.strip()
    urls = [url for url in dict.fromkeys(urls) if url]
    if args.limit is not None:
        urls = urls[: args.limit]
    result_map = load_existing(output_path, force=args.force)
    remaining = [url for url in urls if url not in result_map]
    print(f"inspection version: {INSPECTION_VERSION}", flush=True)
    print(f"unique URLs: {len(urls):,}", flush=True)
    print(f"remaining this run: {len(remaining):,}", flush=True)
    if not remaining:
        print("All URLs are already complete.", flush=True)
        return
    async with async_playwright() as playwright:
        launch_options: dict[str, Any] = {"headless": not args.headful, "args": ["--disable-dev-shm-usage"]}
        if args.executable_path:
            launch_options["executable_path"] = args.executable_path
        elif sys.platform.startswith("linux"):
            system_chromium = shutil.which("chromium") or shutil.which("google-chrome")
            if system_chromium:
                launch_options["executable_path"] = system_chromium
        browser: Browser = await playwright.chromium.launch(**launch_options)
        context = await browser.new_context(user_agent=USER_AGENT, locale="en-US", timezone_id="UTC", viewport={"width": 1440, "height": 1000}, ignore_https_errors=True, extra_http_headers={"Accept-Language": "en-US,en;q=0.9"})
        try:
            for batch_start in range(0, len(remaining), args.batch_size):
                batch_urls = remaining[batch_start: batch_start + args.batch_size]
                valid_urls: list[str] = []
                for url in batch_urls:
                    malformed, reason = is_malformed_url(url)
                    if malformed:
                        result_map[url] = malformed_result(url, reason)
                    else:
                        valid_urls.append(url)
                precheck_map = await run_optional_precheck_batch(valid_urls, enabled=args.http_precheck, timeout_seconds=args.request_timeout_seconds, concurrency=max(10, args.concurrency * 4))
                browser_jobs = [(url, precheck_map[url]) for url in valid_urls]
                if browser_jobs:
                    browser_results = await run_browser_batch(context, browser_jobs, concurrency=args.concurrency, navigation_timeout_ms=args.navigation_timeout_ms, page_consent_wait_ms=args.page_consent_wait_ms, pv_wait_ms=args.pv_wait_ms)
                    for result in browser_results:
                        result_map[str(result["normalized_url"])] = result
                save_results(result_map, output_path)
        finally:
            save_results(result_map, output_path)
            await context.close()
            await browser.close()
    print("Inspection complete.", flush=True)
    print(f"Saved to: {output_path.resolve()}", flush=True)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect URLs and capture generalized first-page-view measurement fields.")
    parser.add_argument("--input", required=True, help="CSV containing normalized_url")
    parser.add_argument("--output", required=True, help="Checkpoint/result CSV")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--navigation-timeout-ms", type=int, default=35_000)
    parser.add_argument("--page-consent-wait-ms", type=int, default=500)
    parser.add_argument("--pv-wait-ms", type=int, default=12_000)
    parser.add_argument("--http-precheck", action="store_true")
    parser.add_argument("--request-timeout-seconds", type=int, default=12)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--executable-path", default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    return parser

def main() -> None:
    args = build_parser().parse_args()
    if args.concurrency < 1:
        raise ValueError("concurrency must be >= 1")
    if args.batch_size < 1:
        raise ValueError("batch-size must be >= 1")
    if args.limit is not None and args.limit < 1:
        raise ValueError("limit must be >= 1")
    asyncio.run(async_main(args))

if __name__ == "__main__":
    main()
