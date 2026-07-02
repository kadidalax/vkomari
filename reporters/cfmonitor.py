# CF-VPS-Monitor reporter: keeps an Agent WebSocket so live viewer policy works.
import asyncio, json, os, threading, time
from urllib.parse import quote

import httpx
import websockets

from agent import VirtualAgent

COUNTRY_REGIONS = {
    "CN":"Shanghai, China, CN","US":"Los Angeles, United States, US",
    "JP":"Tokyo, Japan, JP","DE":"Frankfurt, Germany, DE",
    "GB":"London, United Kingdom, GB","HK":"Hong Kong, Hong Kong, HK",
    "SG":"Singapore, Singapore, SG","KR":"Seoul, South Korea, KR",
    "NL":"Amsterdam, Netherlands, NL","FR":"Paris, France, FR",
    "CA":"Toronto, Canada, CA","AU":"Sydney, Australia, AU",
    "IN":"Mumbai, India, IN","BR":"Sao Paulo, Brazil, BR",
    "RU":"Moscow, Russia, RU","TW":"Taipei, Taiwan, TW",
    "AE":"Dubai, United Arab Emirates, AE",
    "CLOUDFLARE":"Cloudflare Edge Network, Cloudflare, CLOUDFLARE",
    "UNKNOWN":"Unknown, Unknown, UNKNOWN",
}

cf_diag = {"reporters":[],"lastUpdate":0}
_http_proxy = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
_https_proxy = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")

def _get_proxy(target_url: str):
    if target_url.startswith("https://") and _https_proxy:
        return _https_proxy
    if target_url.startswith("http://") and _http_proxy:
        return _http_proxy
    return None

class CFMonitorReporter:
    def __init__(self, config: dict):
        self.config = config
        self.agent = VirtualAgent(config)
        self.tick_count = 0
        self.info_sent = False
        self.last_send_at = 0
        self.last_send_log_at = 0
        self.fail_count = 0
        self.force_next_send = True
        self.policy = {"mode":"idle","sample_interval_sec":120,"report_interval_sec":120,"viewer_count":0,"report_now":False}
        self._stop = threading.Event()
        self._thread = None
        self.diag = {"sendCount":0,"lastSendTs":0,"wsState":"closed"}

    @property
    def http_base(self) -> str:
        return str(self.config.get("cfmonitor_server","")).rstrip("/")

    @property
    def token(self) -> str:
        return str(self.config.get("cfmonitor_token",""))

    def ws_url(self) -> str:
        base = self.http_base
        if base.startswith("https://"):
            base = "wss://" + base[8:]
        elif base.startswith("http://"):
            base = "ws://" + base[7:]
        return "{}/api/clients/report?token={}".format(base, quote(self.token, safe=""))

    def basic_info_url(self) -> str:
        return "{}/api/clients/uploadBasicInfo?token={}".format(self.http_base, quote(self.token, safe=""))

    def headers(self) -> dict:
        return {"Authorization":"Bearer "+self.token,"Content-Type":"application/json"}

    def report_interval_sec(self) -> int:
        return max(1, min(int(self.policy.get("sample_interval_sec",120)), 3600))

    def _apply_policy(self, data: dict):
        old_mode = self.policy.get("mode")
        self.policy.update({
            "mode": data.get("mode", "idle"),
            "sample_interval_sec": data.get("sample_interval_sec", data.get("report_interval_sec", 120)),
            "report_interval_sec": data.get("report_interval_sec", data.get("sample_interval_sec", 120)),
            "viewer_count": data.get("viewer_count", 0),
            "report_now": bool(data.get("report_now")),
        })
        if self.policy.get("mode") != old_mode:
            print("[vKomari] {} policy: mode={} interval={}s viewers={}".format(
                self.log_name(), self.policy.get("mode"),
                self.report_interval_sec(), self.policy.get("viewer_count")))

    def region_label(self) -> str:
        region = (self.config.get("region") or "").strip()
        if region: return region
        fake_ip = str(self.config.get("fake_ip") or "").strip()
        if fake_ip:
            first = fake_ip.split(".")[0] if "." in fake_ip else fake_ip
            try:
                octet = int(first)
                if octet < 50: return "New York, United States, US"
                elif octet < 100: return "London, United Kingdom, GB"
                elif octet < 150: return "Tokyo, Japan, JP"
                elif octet < 200: return "Singapore, Singapore, SG"
                else: return "Sydney, Australia, AU"
            except (ValueError, TypeError): pass
        return "Los Angeles, United States, US"

    def basic_info(self) -> dict:
        c = self.config
        return {
            "cpu_name":c.get("cpu_model","Virtual CPU"),
            "cpu_cores":int(c.get("cpu_cores",1)),
            "cpu_physical_cores":int(c.get("cpu_cores",1)),
            "arch":c.get("arch","amd64"),"os":c.get("os","Linux"),
            "kernel_version":c.get("kernel_version",""),
            "ipv4":c.get("fake_ip") or c.get("ipv4",""),
            "ipv6":c.get("ipv6",""),
            "mem_total":self.agent.usable["ram"],
            "swap_total":self.agent.usable["swap"],
            "disk_total":self.agent.usable["disk"],
            "gpu_name":c.get("gpu_name",""),
            "virtualization":c.get("virtualization","kvm"),
            "version":"1.0.0"
        }

    async def upload_basic_info(self):
        try:
            proxy = _get_proxy(self.http_base)
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), proxy=proxy) as c:
                await c.post(self.basic_info_url(), headers=self.headers(), json=self.basic_info())
            self.info_sent = True
            self.fail_count = 0
        except Exception as e:
            self.fail_count += 1
            if self.fail_count <= 3:
                print("[vKomari] {} basicInfo failed: {}".format(self.log_name(), e))

    def build_report(self, now: float) -> dict:
        stats = self.agent.generate_stats(self.tick_count)
        self.tick_count += 1
        interval = self.report_interval_sec()
        return {
            "cpu":stats["cpu"],"ram":int(self.agent.usable["ram"]*stats["mem"]/100),
            "ram_total":self.agent.usable["ram"],
            "temp":round(stats["temp"],1),
            "disk":int(self.agent.usable["disk"]*stats["disk"]/100),
            "disk_total":self.agent.usable["disk"],
            "net_in":stats["up"],"net_out":stats["down"],
            "net_total_in":stats["totalUp"],"net_total_out":stats["totalDown"],
            "process_count":stats["proc"],"connections":stats["conn"],
            "connections_udp":stats["connUdp"],"uptime":stats["uptime"],
            "timestamp":int(now*1000),"version":"1.0.0",
            "name":self.config.get("name",""),
            "report_interval":interval,"interval_sec":interval,
            "ipv4":self.config.get("fake_ip",""),"ipv6":self.config.get("ipv6",""),
            "region":self.region_label(),"basic_info":self.basic_info(),"gpus":[]
        }

    def log_name(self) -> str:
        return "cfmonitor {}".format(self.config.get("name") or self.config.get("client_uuid","")).strip()

    def log_send(self, now: float):
        now_ms = int(now * 1000)
        if now_ms - self.last_send_log_at < 30000: return
        self.last_send_log_at = now_ms
        print("[vKomari] {} report ws mode={}".format(self.log_name(), self.policy.get("mode","idle")))

    async def _send_ws_report(self, ws):
        now = time.time()
        if not self.info_sent:
            await self.upload_basic_info()
        await ws.send(json.dumps({"type":"reports","reports":[self.build_report(now)]}))
        now_ms = int(now * 1000)
        self.last_send_at = now_ms
        self.diag["sendCount"] += 1
        self.diag["lastSendTs"] = now_ms
        self.log_send(now)
        self.fail_count = 0

    async def _ws_session(self):
        self.diag["wsState"] = "connecting"
        try:
            async with websockets.connect(
                self.ws_url(),
                additional_headers=self.headers(),
                proxy=True,
                open_timeout=15,
                ping_interval=30,
                ping_timeout=20,
            ) as ws:
                self.diag["wsState"] = "open"
                next_send = 0.0
                while not self._stop.is_set():
                    now = time.time()
                    if self.force_next_send or now >= next_send:
                        self.force_next_send = False
                        await self._send_ws_report(ws)
                        next_send = time.time() + self.report_interval_sec()
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=max(0.2, min(1.0, next_send - time.time())))
                    except asyncio.TimeoutError:
                        continue
                    data = json.loads(msg)
                    if isinstance(data, dict) and data.get("type") == "policy":
                        self._apply_policy(data)
                        if data.get("report_now"):
                            self.force_next_send = True
        except Exception as e:
            self.diag["wsState"] = "error"
            self.fail_count += 1
            if self.fail_count <= 3:
                print("[vKomari] {} ws failed: {}".format(self.log_name(), e))

    async def _ws_loop(self):
        while not self._stop.is_set():
            await self._ws_session()
            if not self._stop.is_set():
                await asyncio.sleep(5)
        self.diag["wsState"] = "closed"

    def _run_ws_loop(self):
        asyncio.run(self._ws_loop())

    def close(self):
        self._stop.set()

    async def send(self):
        if not self._thread or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run_ws_loop, daemon=True)
            self._thread.start()
