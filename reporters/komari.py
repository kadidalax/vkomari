# Komari panel reporter: HTTP POST, sends every 1 second.
import json
import time
import threading
import httpx
from urllib.parse import quote
from agent import VirtualAgent
from db import get_db

BASIC_INFO_INTERVAL_SEC = 300


def country_flag(region: str) -> str:
    raw = str(region or "").strip()
    if not raw:
        return ""
    if "," in raw:
        import re
        match = re.search(r"([A-Za-z]{2})\s*$", raw)
        if match:
            code = match.group(1).upper()
            return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in code)
        return raw
    code = raw.upper()
    if not all("A" <= c <= "Z" for c in code) or len(code) != 2:
        return raw
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in code)


class KomariReporter:
    def __init__(self, config: dict):
        self.config = config
        self.agent = VirtualAgent(config)
        self.tick_count = 0
        self.info_sent = False
        self.last_basic_info_at = 0
        self.last_attempt_at = 0
        self.last_send_log_at = 0
        self.fail_count = 0
        self._register_lock = threading.Lock()
        self._registering = False

    @property
    def http_base(self) -> str:
        return str(self.config.get("komari_server", "")).rstrip("/")

    @property
    def report_url(self) -> str:
        token = quote(str(self.config.get("komari_token", "")), safe="")
        return "{}/api/clients/report?token={}".format(self.http_base, token)

    async def _post(self, client, url: str, **kwargs):
        if client is not None:
            return await client.post(url, **kwargs)
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as c:
            return await c.post(url, **kwargs)

    def retry_interval_sec(self) -> int:
        try:
            base = max(1, min(int(self.config.get("report_interval") or 1), 3600))
        except (ValueError, TypeError):
            base = 1
        if self.fail_count:
            return min(60, max(base, 2 ** min(self.fail_count, 5)))
        return base

    def basic_info_interval_sec(self) -> int:
        return BASIC_INFO_INTERVAL_SEC

    async def ensure_token(self, client=None) -> bool:
        if self.config.get("komari_token"):
            return True
        key = str(self.config.get("komari_auto_discovery") or "").strip()
        if not key:
            return False
        with self._register_lock:
            if self.config.get("komari_token"):
                return True
            if self._registering:
                return False
            self._registering = True
        name = quote(str(self.config.get("name") or self.config.get("client_uuid") or "vkomari"), safe="")
        url = "{}/api/clients/register?name={}".format(self.http_base, name)
        try:
            resp = await self._post(
                client,
                url,
                json={"key": key},
                headers={"Authorization": "Bearer {}".format(key), "Content-Type": "application/json"},
            )
            if resp.status_code >= 400:
                raise RuntimeError("register returned {}: {}".format(resp.status_code, resp.text[:200]))
            payload = resp.json()
            if payload.get("status") != "success":
                raise RuntimeError(payload.get("message") or "auto-discovery register failed")
            data = payload.get("data") or {}
            token = str(data.get("token") or "")
            uuid = str(data.get("uuid") or "")
            if not token:
                raise RuntimeError("auto-discovery response missing token")
            self.config["komari_token"] = token
            if uuid:
                self.config["client_uuid"] = uuid
            self._persist_auto_discovery_result(token, uuid)
            self.fail_count = 0
            print("[vKomari] {} auto-discovery registered".format(self.log_name()))
            return True
        except Exception as e:
            self.fail_count += 1
            if self.fail_count <= 3:
                print("[vKomari] {} auto-discovery failed: {}".format(self.log_name(), e))
            return False
        finally:
            with self._register_lock:
                self._registering = False

    def _persist_auto_discovery_result(self, token: str, uuid: str):
        node_id = self.config.get("id")
        if not node_id:
            return
        db = get_db()
        try:
            if uuid:
                db.execute(
                    "UPDATE nodes SET komari_token = ?, client_uuid = ? WHERE id = ?",
                    (token, uuid, node_id),
                )
            else:
                db.execute("UPDATE nodes SET komari_token = ? WHERE id = ?", (token, node_id))
            db.commit()
        finally:
            db.close()

    async def upload_basic_info(self, client=None):
        c = self.config
        region = country_flag(str(c.get("region", "")))
        info = {
            "name": c.get("name", ""),
            "cpu_name": c.get("cpu_model", "Virtual CPU"),
            "cpu_cores": int(c.get("cpu_cores", 1)),
            "cpu_physical_cores": int(c.get("cpu_cores", 1)),
            "arch": c.get("arch", "amd64"),
            "os": c.get("os", "Linux"),
            "kernel_version": c.get("kernel_version", ""),
            "ipv4": c.get("fake_ip") or c.get("ipv4", ""),
            "ipv6": c.get("ipv6", ""),
            "mem_total": self.agent.usable["ram"],
            "swap_total": self.agent.usable["swap"],
            "disk_total": self.agent.usable["disk"],
            "gpu_name": c.get("gpu_name", ""),
            "virtualization": c.get("virtualization", "kvm"),
            "weight": int(c.get("sort_order") or 0),
            "version": "1.0.0"
        }
        if region:
            info["region"] = region
        token_enc = quote(str(c.get("komari_token", "")), safe="")
        try:
            await self._post(
                client,
                "{}/api/clients/uploadBasicInfo?token={}".format(self.http_base, token_enc),
                json=info,
            )
            self.info_sent = True
            self.last_basic_info_at = time.time()
            self.fail_count = 0
        except Exception as e:
            self.fail_count += 1
            if self.fail_count <= 3:
                print("[vKomari] {} basicInfo failed: {}".format(self.log_name(), e))

    def build_report(self) -> dict:
        stats = self.agent.generate_stats(self.tick_count)
        self.tick_count += 1
        return {
            "cpu": {"usage": round(stats["cpu"], 1)},
            "ram": {
                "total": self.agent.usable["ram"],
                "used": round(self.agent.usable["ram"] * stats["mem"] / 100)
            },
            "swap": {
                "total": self.agent.usable["swap"],
                "used": round(self.agent.usable["swap"] * stats["swap"] / 100)
            },
            "load": {
                "load1": stats["load1"],
                "load5": stats["load5"],
                "load15": stats["load15"]
            },
            "disk": {
                "total": self.agent.usable["disk"],
                "used": round(self.agent.usable["disk"] * stats["disk"] / 100)
            },
            "network": {
                "up": stats["up"], "down": stats["down"],
                "totalUp": stats["totalUp"], "totalDown": stats["totalDown"]
            },
            "connections": {"tcp": stats["conn"], "udp": stats["connUdp"]},
            "uptime": stats["uptime"],
            "process": stats["proc"],
            "gpu": {},
            "message": ""
        }

    def log_name(self) -> str:
        name = self.config.get("name") or self.config.get("client_uuid", "")
        return "komari {}".format(name).strip()

    def log_send(self):
        now = int(time.time() * 1000)
        if now - self.last_send_log_at < 30000:
            return
        self.last_send_log_at = now
        print("[vKomari] {} report http".format(self.log_name()))

    async def send(self, client=None):
        now = time.time()
        if self.last_attempt_at and now - self.last_attempt_at < self.retry_interval_sec():
            return
        self.last_attempt_at = now
        if not await self.ensure_token(client):
            return
        if not self.info_sent or now - self.last_basic_info_at >= self.basic_info_interval_sec():
            await self.upload_basic_info(client)
        try:
            await self._post(client, self.report_url, json=self.build_report())
            self.log_send()
            self.fail_count = 0
        except Exception as e:
            self.fail_count += 1
            if self.fail_count <= 3:
                print("[vKomari] {} send failed: {}".format(self.log_name(), e))
