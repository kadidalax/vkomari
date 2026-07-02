# Node CRUD routes
import json
import uuid
import random
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from auth import auth_required
from db import get_db, get_nodes, save_node, normalize_node_data, NODE_FIELDS

router = APIRouter()


# These are plain functions (not route handlers 鈥?those are in main.py)
def _random_uptime_base():
    return random.randint(1, 30) * 86400


def _default_report_interval(data):
    return 3 if data.get("cfmonitor_server") or data.get("cfmonitor_token") else 1


def _norm_server(value):
    return str(value or "").strip().rstrip("/")


def _find_auto_discovery_import(db, node):
    name = str(node.get("name") or "").strip()
    server = _norm_server(node.get("komari_server"))
    key = str(node.get("komari_auto_discovery") or "").strip()
    if not (name and server and key and not node.get("komari_token")):
        return None
    rows = db.execute(
        "SELECT * FROM nodes WHERE name = ? AND komari_auto_discovery = ?",
        (name, key),
    ).fetchall()
    for row in rows:
        if _norm_server(row["komari_server"]) == server:
            return dict(row)
    return None


def _list_nodes(request: Request):
    return get_nodes()


async def _create_node(request: Request):
    d = await request.json()
    if not d.get("client_uuid"):
        d["client_uuid"] = str(uuid.uuid4())
    if d.get("fake_ip") is None:
        d["fake_ip"] = ""
    if not d.get("report_interval"):
        d["report_interval"] = _default_report_interval(d)
    if not d.get("uptime_base"):
        d["uptime_base"] = _random_uptime_base()
    return save_node(d)


async def _toggle_node(request: Request):
    body = await request.json()
    node_id = body.get("id")
    enabled = 1 if body.get("enabled") else 0
    db = get_db()
    try:
        db.execute("UPDATE nodes SET enabled = ? WHERE id = ?", (enabled, node_id))
        db.commit()
    finally:
        db.close()
    return {"status": "ok"}


async def _batch_nodes(request: Request):
    body = await request.json()
    action = body.get("action")
    enabled = 1 if action == "start" else 0
    db = get_db()
    try:
        db.execute("UPDATE nodes SET enabled = ?", (enabled,))
        db.commit()
    finally:
        db.close()
    return {"status": "ok"}


async def _reorder_nodes(request: Request):
    body = await request.json()
    updates = body.get("updates", [])
    if not isinstance(updates, list):
        return JSONResponse({"error": "Invalid data"}, status_code=400)
    db = get_db()
    try:
        for u in updates:
            uid = u.get("id")
            if not uid:
                continue
            parts = []
            params = []
            if isinstance(u.get("sort_order"), (int, float)):
                parts.append("sort_order = ?")
                params.append(u["sort_order"])
            if "group_name" in u:
                parts.append("group_name = ?")
                params.append(u["group_name"])
            if parts:
                params.append(uid)
                db.execute(f"UPDATE nodes SET {', '.join(parts)} WHERE id = ?", params)
        db.commit()
    finally:
        db.close()
    return {"status": "ok", "count": len(updates)}


async def _delete_node(request: Request):
    body = await request.json()
    node_id = body.get("id")
    db = get_db()
    try:
        db.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        db.commit()
    finally:
        db.close()
    return {"status": "ok"}


async def _batch_delete(request: Request):
    body = await request.json()
    ids = body.get("ids", [])
    if not isinstance(ids, list) or len(ids) == 0:
        return JSONResponse({"error": "No ids"}, status_code=400)
    db = get_db()
    try:
        for nid in ids:
            db.execute("DELETE FROM nodes WHERE id = ?", (nid,))
        db.commit()
    finally:
        db.close()
    return {"status": "ok", "count": len(ids)}


async def _import_nodes(request: Request):
    body = await request.json()
    nodes = body.get("nodes", [])
    if not isinstance(nodes, list):
        return JSONResponse({"error": "Invalid data"}, status_code=400)
    nodes = sorted(nodes, key=lambda n: str((n or {}).get("name") or ""), reverse=True)
    db = get_db()
    fields = NODE_FIELDS
    created = 0
    updated = 0
    try:
        for n in nodes:
            n = normalize_node_data(n)
            existing = _find_auto_discovery_import(db, n)
            if existing:
                if not n.get("komari_token"):
                    n["komari_token"] = existing.get("komari_token")
                if not n.get("client_uuid"):
                    n["client_uuid"] = existing.get("client_uuid")
            elif not n.get("client_uuid"):
                n["client_uuid"] = str(uuid.uuid4())
            if not n.get("fake_ip"):
                n["fake_ip"] = ""
            if not n.get("report_interval"):
                n["report_interval"] = _default_report_interval(n)
            if not n.get("uptime_base"):
                n["uptime_base"] = _random_uptime_base()
            values = [n.get(k) for k in fields]
            if existing:
                set_clause = ", ".join(f"{k} = ?" for k in fields)
                db.execute(f"UPDATE nodes SET {set_clause} WHERE id = ?", values + [existing["id"]])
                updated += 1
            else:
                placeholders = ", ".join("?" for _ in fields)
                db.execute(f"INSERT INTO nodes ({', '.join(fields)}) VALUES ({placeholders})", values)
                created += 1
        db.commit()
    finally:
        db.close()
    return {"status": "ok", "count": len(nodes), "created": created, "updated": updated}
