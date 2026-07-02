import asyncio
import json
import os
import subprocess
import sys

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
    from reporters import komari as komari_module
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

    original_client = komari_module.httpx.AsyncClient
    komari_module.httpx.AsyncClient = FakeClient
    try:
        reporter = KomariReporter({
            "name": "AutoNode",
            "komari_server": "https://komari.example.com",
            "komari_auto_discovery": "ad-secret",
            "ram_total": 512,
            "disk_total": 1024,
        })
        asyncio.run(reporter.send())
    finally:
        komari_module.httpx.AsyncClient = original_client

    assert calls[0][0] == "https://komari.example.com/api/clients/register?name=AutoNode"
    assert calls[0][2]["Authorization"] == "Bearer ad-secret"
    assert reporter.config["komari_token"] == "registered-token"
    assert reporter.config["client_uuid"] == "komari-uuid"
    assert any("uploadBasicInfo?token=registered-token" in call[0] for call in calls)
    assert any("report?token=registered-token" in call[0] for call in calls)


if __name__ == "__main__":
    test_install_script_parses_komari_auto_discovery()
    test_komari_reporter_registers_auto_discovery_before_reporting()
