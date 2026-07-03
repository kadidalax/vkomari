# Background scheduler: runs the dual-panel simulation loop.
# ponytail: persisted reporter dict keyed by node id, recreated on config changes.
import asyncio
import os
import time
import json
import threading
import httpx
from db import ensure_schema, get_enabled_nodes, set_setting, get_setting
from reporters.komari import KomariReporter
from reporters.cfmonitor import CFMonitorReporter

TICK_SECONDS = 1


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


KOMARI_MAX_REPORTS_PER_TICK = _env_int("VKOMARI_KOMARI_MAX_RPS", 50)
_scheduler_stop = threading.Event()
_scheduler_thread = None
_komari_cursor = 0

# Persisted reporters across ticks -- keyed by a stable node identity.
_komari_reporters = {}   # node_id -> KomariReporter
_komari_configs = {}     # node_id -> config fingerprint
_cfmonitor_reporters = {} # node_id -> CFMonitorReporter
_cfmonitor_configs = {}   # node_id -> config fingerprint


def _ensure_schema_safe():
    try:
        ensure_schema()
    except Exception:
        pass


def _cfmonitor_fingerprint(node):
    keys = [
        "cfmonitor_server", "cfmonitor_token", "name", "client_uuid", "fake_ip",
        "ipv6", "region", "cpu_model", "cpu_cores", "ram_total", "ram_unit",
        "swap_total", "swap_unit", "disk_total", "disk_unit", "load_profile",
        "report_interval",
    ]
    return json.dumps({k: node.get(k) for k in keys}, sort_keys=True, ensure_ascii=False)


def _komari_fingerprint(node):
    keys = [
        "komari_server", "komari_token", "komari_auto_discovery", "name", "client_uuid",
        "fake_ip", "ipv6", "region", "cpu_model", "cpu_cores", "ram_total", "ram_unit",
        "swap_total", "swap_unit", "disk_total", "disk_unit", "load_profile", "report_interval",
        "sort_order",
    ]
    return json.dumps({k: node.get(k) for k in keys}, sort_keys=True, ensure_ascii=False)


def _next_komari_batch(reporters):
    global _komari_cursor
    if len(reporters) <= KOMARI_MAX_REPORTS_PER_TICK:
        return reporters
    start = _komari_cursor % len(reporters)
    end = start + KOMARI_MAX_REPORTS_PER_TICK
    _komari_cursor = end % len(reporters)
    return (reporters + reporters)[start:end]


async def _async_tick(komari_client=None):
    nodes = get_enabled_nodes()

    # Build set of current node ids
    current_komari_ids = set()
    current_cf_ids = set()
    komari_reporters = []
    cf_reporters = []

    for node in nodes:
        nid = str(node["id"])

        if node.get("komari_server") and (node.get("komari_token") or node.get("komari_auto_discovery")):
            current_komari_ids.add(nid)
            fingerprint = _komari_fingerprint(node)
            if nid in _komari_reporters and _komari_configs.get(nid) != fingerprint:
                del _komari_reporters[nid]
            if nid not in _komari_reporters:
                _komari_reporters[nid] = KomariReporter(dict(node))
                _komari_configs[nid] = fingerprint
            komari_reporters.append(_komari_reporters[nid])

        if node.get("cfmonitor_server") and node.get("cfmonitor_token"):
            current_cf_ids.add(nid)
            fingerprint = _cfmonitor_fingerprint(node)
            if nid in _cfmonitor_reporters and _cfmonitor_configs.get(nid) != fingerprint:
                _cfmonitor_reporters[nid].close()
                del _cfmonitor_reporters[nid]
            if nid not in _cfmonitor_reporters:
                _cfmonitor_reporters[nid] = CFMonitorReporter(dict(node))
                _cfmonitor_configs[nid] = fingerprint
            cf_reporters.append(_cfmonitor_reporters[nid])

    # Clean up stale reporters
    for nid in list(_komari_reporters.keys()):
        if nid not in current_komari_ids:
            del _komari_reporters[nid]
            _komari_configs.pop(nid, None)
    for nid in list(_cfmonitor_reporters.keys()):
        if nid not in current_cf_ids:
            _cfmonitor_reporters[nid].close()
            del _cfmonitor_reporters[nid]
            _cfmonitor_configs.pop(nid, None)

    # Run all reporters concurrently, never let one crash stop others.
    # Komari reporters share one long-lived AsyncClient from the scheduler loop.
    tasks = [r.send(komari_client) for r in _next_komari_batch(komari_reporters)] + [r.send() for r in cf_reporters]
    if tasks:
        await asyncio.gather(
            *tasks,
            return_exceptions=True
        )

    # Update diagnostics every ~5s
    now_ms = time.time() * 1000
    try:
        last_ts = get_setting("cf_diag_ts") or 0
    except Exception:
        last_ts = 0

    if now_ms - last_ts > 5000:
        cf_list = list(_cfmonitor_reporters.values())
        if cf_list:
            diag_data = [r.diag for r in cf_list]
            try:
                set_setting("cf_diag_ts", int(now_ms))
                set_setting("cf_diag", json.dumps(diag_data))
            except Exception:
                pass


async def _scheduler_loop():
    limits = httpx.Limits(max_connections=32, max_keepalive_connections=16, keepalive_expiry=120)
    timeout = httpx.Timeout(15.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout, limits=limits) as komari_client:
        while not _scheduler_stop.is_set():
            started = time.monotonic()
            try:
                await _async_tick(komari_client)
            except Exception as e:
                print("[vKomari] Scheduler tick error: {}".format(e))
            await asyncio.sleep(max(0.1, TICK_SECONDS - (time.monotonic() - started)))


def stop_scheduler():
    _scheduler_stop.set()


def start_scheduler():
    global _scheduler_thread
    _ensure_schema_safe()
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(target=lambda: asyncio.run(_scheduler_loop()), daemon=True)
    _scheduler_thread.start()
    print("[vKomari] Scheduler started (1s tick)")
