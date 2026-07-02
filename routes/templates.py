# Templates routes
import json
from fastapi import APIRouter, Request
from db import get_db, get_templates

router = APIRouter()


@router.get("/")
async def list_templates(request: Request):
    return get_templates()


@router.post("/")
async def create_template(request: Request):
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


@router.post("/update")
async def update_template(request: Request):
    body = await request.json()
    tid = body.get("id")
    if not tid:
        return {"error": "Missing template id"}
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


@router.post("/delete")
async def delete_template(request: Request):
    body = await request.json()
    tid = body.get("id")
    db = get_db()
    try:
        db.execute("DELETE FROM templates WHERE id = ?", (tid,))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()
