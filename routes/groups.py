# Groups routes
from fastapi import APIRouter, Request
from db import get_db

router = APIRouter()


@router.post("/rename")
async def rename_group(request: Request):
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
