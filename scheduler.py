# Background scheduler: runs the dual-panel simulation loop.
# ponytail: persisted reporter dict keyed by node id, recreated on config changes.
import asyncio
import time
import json
import os
import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from db import ensure_schema, get_enabled_nodes, set_setting, get_setting
from reporters.komari import KomariReporter
from reporters.cfmonitor import CFMonitorReporter, cf_diag

scheduler = BackgroundScheduler()

# Persisted reporters across ticks -- keyed by a stable node identity.
_komari_reporters = {}   # node_id -> KomariReporter
_cfmonitor_reporters = {} # node_id -> CFMonitorReporter


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


async def _async_tick():
    _ensure_schema_safe()
    nodes = get_enabled_nodes()

    # Build set of current node ids
    current_ids = set()
    reporters = []

    for node in nodes:
        nid = str(node["id"])
        current_ids.add(nid)

        if node.get("komari_server") and node.get("komari_token"):
            if nid not in _komari_reporters:
                _komari_reporters[nid] = KomariReporter(dict(node))
            reporters.append(_komari_reporters[nid])

        if node.get("cfmonitor_server") and node.get("cfmonitor_token"):
            if nid not in _cfmonitor_reporters:
                _cfmonitor_reporters[nid] = CFMonitorReporter(dict(node))
            reporters.append(_cfmonitor_reporters[nid])

    # Clean up stale reporters
    for nid in list(_komari_reporters.keys()):
        if nid not in current_ids:
            del _komari_reporters[nid]
    for nid in list(_cfmonitor_reporters.keys()):
        if nid not in current_ids:
            _cfmonitor_reporters[nid].close()
            del _cfmonitor_reporters[nid]

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
        _sync_tick, "interval", seconds=3, id="vkomari_tick",
        max_instances=2, misfire_grace_time=30
    )
    scheduler.start()
    print("[vKomari] Scheduler started (3s tick)")
