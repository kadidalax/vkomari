# CF-VPS-Monitor reporter: keeps an Agent WebSocket so live viewer policy works.
import asyncio, json, os, threading, time
from urllib.parse import quote

import httpx
import websockets

from agent import VirtualAgent

COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua & Barbuda",
    "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica", "AR": "Argentina",
    "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba", "AZ": "Azerbaijan",
    "BA": "Bosnia & Herzegovina", "BB": "Barbados", "BD": "Bangladesh", "BE": "Belgium",
    "BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Bahrain", "BI": "Burundi", "BJ": "Benin",
    "BM": "Bermuda", "BN": "Brunei", "BO": "Bolivia", "BR": "Brazil", "BS": "Bahamas",
    "BT": "Bhutan", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize", "CA": "Canada",
    "CD": "Congo (DRC)", "CF": "Central African Republic", "CG": "Congo", "CH": "Switzerland",
    "CI": "Cote d'Ivoire", "CK": "Cook Islands", "CL": "Chile", "CM": "Cameroon", "CN": "China",
    "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba", "CV": "Cabo Verde", "CW": "Curacao",
    "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark",
    "DM": "Dominica", "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador",
    "EE": "Estonia", "EG": "Egypt", "ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia",
    "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands", "FM": "Micronesia", "FR": "France",
    "GA": "Gabon", "GB": "United Kingdom", "GD": "Grenada", "GE": "Georgia", "GF": "French Guiana",
    "GH": "Ghana", "GL": "Greenland", "GM": "Gambia", "GN": "Guinea", "GQ": "Equatorial Guinea",
    "GR": "Greece", "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau", "GY": "Guyana",
    "HK": "Hong Kong", "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India", "IQ": "Iraq", "IR": "Iran",
    "IS": "Iceland", "IT": "Italy", "JM": "Jamaica", "JO": "Jordan", "JP": "Japan", "KE": "Kenya",
    "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati", "KM": "Comoros",
    "KN": "St. Kitts & Nevis", "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait",
    "KY": "Cayman Islands", "KZ": "Kazakhstan", "LA": "Laos", "LB": "Lebanon", "LC": "St. Lucia",
    "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesotho", "LT": "Lithuania",
    "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya", "MA": "Morocco", "MC": "Monaco",
    "MD": "Moldova", "ME": "Montenegro", "MG": "Madagascar", "MH": "Marshall Islands",
    "MK": "North Macedonia", "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia", "MO": "Macao",
    "MP": "Northern Mariana Islands", "MR": "Mauritania", "MT": "Malta", "MU": "Mauritius",
    "MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique",
    "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger", "NG": "Nigeria", "NI": "Nicaragua",
    "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru", "NU": "Niue",
    "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru", "PF": "French Polynesia",
    "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan", "PL": "Poland",
    "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal", "PW": "Palau", "PY": "Paraguay",
    "QA": "Qatar", "RE": "Reunion", "RO": "Romania", "RS": "Serbia", "RU": "Russia",
    "RW": "Rwanda", "SA": "Saudi Arabia", "SB": "Solomon Islands", "SC": "Seychelles",
    "SD": "Sudan", "SE": "Sweden", "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia",
    "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal", "SO": "Somalia", "SR": "Suriname",
    "SS": "South Sudan", "ST": "Sao Tome & Principe", "SV": "El Salvador", "SY": "Syria",
    "SZ": "Eswatini", "TD": "Chad", "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan",
    "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga",
    "TR": "Turkey", "TT": "Trinidad & Tobago", "TV": "Tuvalu", "TW": "Taiwan", "TZ": "Tanzania",
    "UA": "Ukraine", "UG": "Uganda", "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan",
    "VA": "Vatican City", "VC": "St. Vincent & Grenadines", "VE": "Venezuela",
    "VG": "British Virgin Islands", "VI": "U.S. Virgin Islands", "VN": "Vietnam", "VU": "Vanuatu",
    "WF": "Wallis & Futuna", "WS": "Samoa", "XK": "Kosovo", "YE": "Yemen", "YT": "Mayotte",
    "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}

REGION_LABELS = {code: "{}, {}".format(name, code) for code, name in COUNTRY_NAMES.items()}

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
        self.force_timer_reset = False
        initial_interval = max(1, min(int(config.get("report_interval") or 3), 3600))
        self.policy = {"mode":"initial","sample_interval_sec":initial_interval,"report_interval_sec":initial_interval,"viewer_count":0,"report_now":False}
        self._stop = threading.Event()
        self._thread = None
        self.diag = {"sendCount":0,"lastSendTs":0,"wsState":"closed","policy":self.policy.copy(),"lastPolicyTs":0}

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
        return "{}/api/clients/report".format(base)

    def basic_info_url(self) -> str:
        return "{}/api/clients/uploadBasicInfo?token={}".format(self.http_base, quote(self.token, safe=""))

    def headers(self) -> dict:
        return {"Authorization":"Bearer "+self.token,"Content-Type":"application/json"}

    def report_interval_sec(self) -> int:
        return self.sample_interval_sec()

    def sample_interval_sec(self) -> int:
        return max(1, min(int(self.policy.get("sample_interval_sec",120)), 3600))

    def upload_interval_sec(self) -> int:
        return max(1, min(int(self.policy.get("report_interval_sec",self.sample_interval_sec())), 3600))

    def _apply_policy(self, data: dict):
        old_policy = dict(self.policy)
        self.policy.update({
            "mode": data.get("mode", "idle"),
            "sample_interval_sec": data.get("sample_interval_sec", data.get("report_interval_sec", 120)),
            "report_interval_sec": data.get("report_interval_sec", data.get("sample_interval_sec", 120)),
            "viewer_count": data.get("viewer_count", 0),
            "report_now": bool(data.get("report_now")),
        })
        self.force_timer_reset = True
        self.diag["policy"] = self.policy.copy()
        self.diag["lastPolicyTs"] = int(time.time() * 1000)
        if self.policy != old_policy:
            print("[vKomari] {} policy: mode={} interval={}s viewers={}".format(
                self.log_name(), self.policy.get("mode"),
                self.sample_interval_sec(), self.policy.get("viewer_count")))

    def region_label(self) -> str:
        region = (self.config.get("region") or "").strip()
        if region:
            code = region.upper()
            if len(code) == 2 and code.isalpha():
                return REGION_LABELS.get(code, code)
            return region
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
            "region":self.region_label(),
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
            "net_in":stats["down"],"net_out":stats["up"],
            "net_total_up":stats["totalUp"],"net_total_down":stats["totalDown"],
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
        await self._send_ws_reports(ws, [self.build_report(time.time())])

    async def _send_ws_reports(self, ws, reports):
        now = time.time()
        if not self.info_sent:
            await self.upload_basic_info()
        await ws.send(json.dumps({"type":"reports","reports":reports}))
        now_ms = int(now * 1000)
        self.last_send_at = now_ms
        self.diag["sendCount"] += len(reports)
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
                pending = []
                next_sample = 0.0
                next_upload = 0.0
                while not self._stop.is_set():
                    now = time.time()
                    sample_interval = self.sample_interval_sec()
                    upload_interval = self.upload_interval_sec()
                    if self.force_next_send:
                        self.force_next_send = False
                        pending.append(self.build_report(now))
                        await self._send_ws_reports(ws, pending)
                        pending = []
                        next_sample = time.time() + sample_interval
                        next_upload = time.time() + upload_interval
                    elif now >= next_sample:
                        pending.append(self.build_report(now))
                        next_sample = now + sample_interval
                        if upload_interval <= sample_interval:
                            await self._send_ws_reports(ws, pending)
                            pending = []
                            next_upload = time.time() + upload_interval
                    elif pending and now >= next_upload:
                        await self._send_ws_reports(ws, pending)
                        pending = []
                        next_upload = time.time() + upload_interval
                    next_event = min(next_sample, next_upload if pending else next_sample)
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=max(0.2, min(1.0, next_event - time.time())))
                    except asyncio.TimeoutError:
                        continue
                    data = json.loads(msg)
                    if isinstance(data, dict) and data.get("type") == "policy":
                        self._apply_policy(data)
                        if self.force_timer_reset:
                            self.force_timer_reset = False
                            next_sample = time.time() + self.sample_interval_sec()
                            next_upload = time.time() + self.upload_interval_sec()
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
