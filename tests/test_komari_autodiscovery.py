import asyncio
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def test_install_script_parses_komari_auto_discovery():
    script = (
        "wget -qO- https://raw.githubusercontent.com/komari-monitor/komari-agent/refs/heads/main/install.sh "
        "| sudo bash -s -- -e https://komari.example.com --auto-discovery test-auto-discovery-key"
    )
    code = f"""
import {{ parseInstallScript }} from './static/js/install.js';
const result = parseInstallScript({json.dumps(script)});
console.log(JSON.stringify(result));
"""
    out = subprocess.check_output(
        ["node", "--input-type=module", "-e", code],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        text=True,
    )
    result = json.loads(out)
    assert result["panel"] == "komari"
    assert result["server"] == "https://komari.example.com"
    assert result["autoDiscovery"] == "test-auto-discovery-key"
    assert result.get("token", "") == ""


def test_komari_reporter_registers_auto_discovery_before_reporting():
    from reporters.komari import KomariReporter

    calls = []

    class FakeResponse:
        status_code = 200
        text = "ok"

        def __init__(self, payload=None):
            self._payload = payload or {}

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None, headers=None):
            calls.append((url, json, headers or {}))
            if "/api/clients/register" in url:
                return FakeResponse({
                    "status": "success",
                    "data": {"uuid": "komari-uuid", "token": "registered-token"},
                })
            return FakeResponse()

    reporter = KomariReporter({
        "name": "AutoNode",
        "komari_server": "https://komari.example.com",
        "komari_auto_discovery": "ad-secret",
        "sort_order": 12,
        "ram_total": 512,
        "disk_total": 1024,
    })
    asyncio.run(reporter.send(FakeClient()))

    assert calls[0][0] == "https://komari.example.com/api/clients/register?name=AutoNode"
    assert calls[0][2]["Authorization"] == "Bearer ad-secret"
    assert reporter.config["komari_token"] == "registered-token"
    assert reporter.config["client_uuid"] == "komari-uuid"
    assert any("uploadBasicInfo?token=registered-token" in call[0] for call in calls)
    basic_info = next(call[1] for call in calls if "uploadBasicInfo" in call[0])
    assert basic_info["name"] == "AutoNode"
    assert basic_info["weight"] == 12
    assert any("report?token=registered-token" in call[0] for call in calls)


def test_komari_auto_discovery_registration_is_singleflight():
    from reporters import komari as komari_module
    from reporters.komari import KomariReporter

    calls = []

    class FakeResponse:
        status_code = 200
        text = "ok"

        def json(self):
            return {"status": "success", "data": {"uuid": "komari-uuid", "token": "registered-token"}}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None, headers=None):
            calls.append(url)
            await asyncio.sleep(0.05)
            return FakeResponse()

    async def run_pair():
        return await asyncio.gather(reporter.ensure_token(), reporter.ensure_token())

    original_client = komari_module.httpx.AsyncClient
    komari_module.httpx.AsyncClient = FakeClient
    try:
        reporter = KomariReporter({
            "name": "AutoNode",
            "komari_server": "https://komari.example.com",
            "komari_auto_discovery": "ad-secret",
        })
        result = asyncio.run(run_pair())
    finally:
        komari_module.httpx.AsyncClient = original_client

    assert calls == ["https://komari.example.com/api/clients/register?name=AutoNode"]
    assert result.count(True) == 1
    assert reporter.config["komari_token"] == "registered-token"


def test_auto_discovery_import_is_idempotent():
    import db as db_module
    from routes import nodes as nodes_module

    class FakeRequest:
        def __init__(self, payload):
            self.payload = payload

        async def json(self):
            return self.payload

    with tempfile.TemporaryDirectory() as tmp:
        db_module.DB_PATH = os.path.join(tmp, "vkomari.db")
        nodes_module.get_db = db_module.get_db
        db_module.ensure_schema()

        node = {
            "name": "CN_中国",
            "komari_server": "https://komari.example.com/",
            "komari_auto_discovery": "auto-discovery-key",
            "komari_token": "",
            "sort_order": 1,
            "report_enabled": True,
            "enabled": True,
        }
        asyncio.run(nodes_module._import_nodes(FakeRequest({"nodes": [node]})))

        conn = db_module.get_db()
        try:
            conn.execute(
                "UPDATE nodes SET komari_token = ?, client_uuid = ? WHERE name = ?",
                ("registered-token", "registered-uuid", "CN_中国"),
            )
            conn.commit()
        finally:
            conn.close()

        node["sort_order"] = 42
        result = asyncio.run(nodes_module._import_nodes(FakeRequest({"nodes": [node]})))
        rows = db_module.get_nodes()

    assert result["created"] == 0
    assert result["updated"] == 1
    assert len(rows) == 1
    assert rows[0]["komari_token"] == "registered-token"
    assert rows[0]["client_uuid"] == "registered-uuid"
    assert rows[0]["sort_order"] == 42


def test_import_nodes_are_inserted_by_name_descending():
    import db as db_module
    from routes import nodes as nodes_module

    class FakeRequest:
        def __init__(self, payload):
            self.payload = payload

        async def json(self):
            return self.payload

    with tempfile.TemporaryDirectory() as tmp:
        db_module.DB_PATH = os.path.join(tmp, "vkomari.db")
        nodes_module.get_db = db_module.get_db
        db_module.ensure_schema()

        asyncio.run(nodes_module._import_nodes(FakeRequest({"nodes": [
            {"name": "AA_节点", "report_enabled": True, "enabled": True},
            {"name": "CC_节点", "report_enabled": True, "enabled": True},
            {"name": "BB_节点", "report_enabled": True, "enabled": True},
        ]})))
        conn = db_module.get_db()
        try:
            names = [r["name"] for r in conn.execute("SELECT name FROM nodes ORDER BY id ASC").fetchall()]
        finally:
            conn.close()

    assert names == ["CC_节点", "BB_节点", "AA_节点"]


if __name__ == "__main__":
    test_install_script_parses_komari_auto_discovery()
    test_komari_reporter_registers_auto_discovery_before_reporting()
    test_komari_auto_discovery_registration_is_singleflight()
    test_auto_discovery_import_is_idempotent()
    test_import_nodes_are_inserted_by_name_descending()
