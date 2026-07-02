# Background scheduler: runs the dual-panel simulation loop.
# ponytail: persisted reporter dict keyed by node id, recreated on config changes.
import asyncio
import time
import json
from apscheduler.schedulers.background import BackgroundScheduler
from db import ensure_schema, get_enabled_nodes, set_setting, get_setting
from reporters.komari import KomariReporter
from reporters.cfmonitor import CFMonitorReporter

scheduler = BackgroundScheduler()

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


def _sync_tick():
    """Sync wrapper that schedules the async tick."""
    try:
        asyncio.run(_async_tick())
    except Exception as e:
        print("[vKomari] Scheduler tick error: {}".format(e))


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


async def _async_tick():
    _ensure_schema_safe()
    nodes = get_enabled_nodes()

    # Build set of current node ids
    current_komari_ids = set()
    current_cf_ids = set()
    reporters = []

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
            reporters.append(_komari_reporters[nid])

        if node.get("cfmonitor_server") and node.get("cfmonitor_token"):
            current_cf_ids.add(nid)
            fingerprint = _cfmonitor_fingerprint(node)
            if nid in _cfmonitor_reporters and _cfmonitor_configs.get(nid) != fingerprint:
                _cfmonitor_reporters[nid].close()
                del _cfmonitor_reporters[nid]
            if nid not in _cfmonitor_reporters:
                _cfmonitor_reporters[nid] = CFMonitorReporter(dict(node))
                _cfmonitor_configs[nid] = fingerprint
            reporters.append(_cfmonitor_reporters[nid])

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

    # Run all reporters concurrently, never let one crash stop others
    if reporters:
        await asyncio.gather(
            *[r.send() for r in reporters],
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


def start_scheduler():
    _ensure_schema_safe()
    scheduler.add_job(
        _sync_tick, "interval", seconds=1, id="vkomari_tick",
        max_instances=1, misfire_grace_time=30
    )
    scheduler.start()
    print("[vKomari] Scheduler started (1s tick)")
