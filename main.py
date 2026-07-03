# vKomari - Virtual Probe Node Manager (Docker VPS Edition)
import json
import time
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from auth import auth_required, hash_password
from db import ensure_schema, get_setting, get_db, get_user, update_password, get_templates
from scheduler import start_scheduler, stop_scheduler

# Import route functions
from routes.auth import router as auth_router_module
from routes.nodes import (
    _list_nodes, _create_node, _toggle_node, _batch_nodes,
    _reorder_nodes, _delete_node, _batch_delete, _import_nodes
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[vKomari] Starting up...")
    ensure_schema()
    start_scheduler()
    print("[vKomari] Ready")
    yield
    print("[vKomari] Shutting down...")
    stop_scheduler()


app = FastAPI(
    title="vKomari",
    description="Virtual Probe Node Manager",
    version="2.0.0",
    lifespan=lifespan
)


# ---- Auth routes (public /api/login) ----
app.include_router(auth_router_module, prefix="/api")


# ---- /api/me ----
@app.get("/api/me")
async def api_me(request: Request, user: dict = Depends(auth_required)):
    return {"username": user["username"]}


# ---- /api/change-password ----
@app.post("/api/change-password")
async def api_change_password(request: Request, user: dict = Depends(auth_required)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    new_password = body.get("newPassword", "")
    if not new_password or len(new_password) < 6:
        return JSONResponse({"error": "Password must be at least 6 characters"}, status_code=400)
    h = hash_password(new_password)
    update_password(user["username"], h["hash"], h["salt"])
    return {"success": True}


# ---- Nodes ----
@app.get("/api/nodes")
def api_list_nodes(request: Request, user: dict = Depends(auth_required)):
    return _list_nodes(request)

@app.post("/api/nodes")
async def api_create_node(request: Request, user: dict = Depends(auth_required)):
    return await _create_node(request)

@app.post("/api/nodes/toggle")
async def api_toggle_node(request: Request, user: dict = Depends(auth_required)):
    return await _toggle_node(request)

@app.post("/api/nodes/batch")
async def api_batch_nodes(request: Request, user: dict = Depends(auth_required)):
    return await _batch_nodes(request)

@app.post("/api/nodes/reorder")
async def api_reorder_nodes(request: Request, user: dict = Depends(auth_required)):
    return await _reorder_nodes(request)

@app.post("/api/nodes/delete")
async def api_delete_node(request: Request, user: dict = Depends(auth_required)):
    return await _delete_node(request)

@app.post("/api/nodes/batchDelete")
async def api_batch_delete(request: Request, user: dict = Depends(auth_required)):
    return await _batch_delete(request)

@app.post("/api/nodes/import")
async def api_import_nodes(request: Request, user: dict = Depends(auth_required)):
    return await _import_nodes(request)


# ---- Groups ----
@app.post("/api/groups/rename")
async def api_rename_group(request: Request, user: dict = Depends(auth_required)):
    body = await request.json()
    old_name = body.get("oldName", "")
    new_name = body.get("newName", "")
    if not old_name or not new_name or old_name == new_name:
        return {"status": "no_change"}
    db = get_db()
    try:
        db.execute("UPDATE nodes SET group_name = ? WHERE group_name = ?", (new_name, old_name))
        db.commit()
    finally:
        db.close()
    return {"status": "ok"}


# ---- Templates ----
@app.get("/api/templates")
def api_list_templates(request: Request, user: dict = Depends(auth_required)):
    return get_templates()

@app.post("/api/templates")
async def api_create_template(request: Request, user: dict = Depends(auth_required)):
    body = await request.json()
    name = body.get("name", "")
    config = body.get("config", {})
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO templates (name, config) VALUES (?, ?)",
            (name, json.dumps(config))
        )
        db.commit()
        return {"status": "ok", "id": cur.lastrowid}
    finally:
        db.close()

@app.post("/api/templates/update")
async def api_update_template(request: Request, user: dict = Depends(auth_required)):
    body = await request.json()
    tid = body.get("id")
    if not tid:
        return JSONResponse({"error": "Missing template id"}, status_code=400)
    name = body.get("name", "")
    config = body.get("config", {})
    db = get_db()
    try:
        db.execute(
            "UPDATE templates SET name = ?, config = ? WHERE id = ?",
            (name, json.dumps(config), tid)
        )
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()

@app.post("/api/templates/delete")
async def api_delete_template(request: Request, user: dict = Depends(auth_required)):
    body = await request.json()
    tid = body.get("id")
    db = get_db()
    try:
        db.execute("DELETE FROM templates WHERE id = ?", (tid,))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


# ---- Health ----
@app.get("/api/health")
async def health():
    return {"status": "ok", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ---- CF Monitor Diagnostics ----
@app.get("/api/cfmonitor/diag")
async def cf_diag_endpoint(request: Request, user: dict = Depends(auth_required)):
    try:
        raw = get_setting("cf_diag")
        reporters = json.loads(raw) if isinstance(raw, str) else raw or []
    except Exception:
        reporters = []
    return {"reporters": reporters, "serverTime": int(time.time() * 1000)}


# ---- Error handler ----
@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    print(f"[vKomari Error] {exc}")
    return JSONResponse({"error": "Internal Server Error", "message": str(exc)}, status_code=500)


# ---- Static files ----
if os.path.isdir("static/js"):
    app.mount("/js", StaticFiles(directory="static/js"), name="js")


@app.get("/")
async def serve_root():
    return FileResponse(os.path.join("static", "index.html"))


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    file_path = os.path.join("static", full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join("static", "index.html"))
