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

def _list_nodes(request: Request):
    return get_nodes()


async def _create_node(request: Request):
    d = await request.json()
    if not d.get("client_uuid"):
        d["client_uuid"] = str(uuid.uuid4())
    if d.get("fake_ip") is None:
        d["fake_ip"] = ""
    if not d.get("report_interval"):
        d["report_interval"] = 3
    if not d.get("uptime_base"):
        d["uptime_base"] = random.randint(1, 7) * 86400
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
    db = get_db()
    fields = NODE_FIELDS
    try:
        for n in nodes:
            n = normalize_node_data(n)
            if not n.get("client_uuid"):
                n["client_uuid"] = str(uuid.uuid4())
            if not n.get("fake_ip"):
                n["fake_ip"] = ""
            if not n.get("report_interval"):
                n["report_interval"] = 3
            if not n.get("uptime_base"):
                n["uptime_base"] = random.randint(1, 7) * 86400
            values = [n.get(k) for k in fields]
            placeholders = ", ".join("?" for _ in fields)
            db.execute(f"INSERT INTO nodes ({', '.join(fields)}) VALUES ({placeholders})", values)
        db.commit()
    finally:
        db.close()
    return {"status": "ok", "count": len(nodes)}
