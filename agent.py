# Virtual probe data generator 鈥?deterministic demo-realistic VPS metrics.
# ponytail: stateless waves/pulses; no DB writes per sample.
# Ported from JS agent.js

import hashlib
import math
import time

MB = 1048576

CPU_PROFILES = {
    "low": {
        "ranges": [(0, 10, 25), (10, 25, 25), (25, 45, 25), (45, 65, 15), (65, 85, 7), (85, 100, 3)],
        "cadence": (4, 10), "chase": 0.45, "jitter": 6,
    },
    "mid": {
        "ranges": [(0, 10, 5), (10, 25, 15), (25, 45, 25), (45, 65, 25), (65, 85, 20), (85, 100, 10)],
        "cadence": (3, 7), "chase": 0.60, "jitter": 9,
    },
    "high": {
        "ranges": [(0, 10, 1), (10, 25, 3), (25, 45, 8), (45, 65, 16), (65, 85, 32), (85, 100, 40)],
        "cadence": (2, 5), "chase": 0.75, "jitter": 12,
    },
}

PROFILE_DEFAULTS = {
    "low": {
        "cpu_min": 0, "cpu_max": 35, "cpu_rest": 0.0,
        "cpu_burst_period1": 22, "cpu_burst_period2": 55, "cpu_burst_period3": 9,
        "cpu_burst_amp": 0.85,
        "mem_min": 8, "mem_max": 18, "swap_min": 0, "swap_max": 2,
        "disk_min": 8, "disk_max": 28,
        "net_min": 10000, "net_max": 200000,
        "conn_min": 2, "conn_max": 25,
        "proc_min": 35, "proc_max": 70
    },
    "mid": {
        "cpu_min": 0, "cpu_max": 65, "cpu_rest": 0.01,
        "cpu_burst_period1": 11, "cpu_burst_period2": 31, "cpu_burst_period3": 6,
        "cpu_burst_amp": 0.75,
        "mem_min": 35, "mem_max": 55, "swap_min": 0, "swap_max": 8,
        "disk_min": 30, "disk_max": 58,
        "net_min": 102400, "net_max": 1024000,
        "conn_min": 30, "conn_max": 120,
        "proc_min": 70, "proc_max": 140
    },
    "high": {
        "cpu_min": 0, "cpu_max": 95, "cpu_rest": 0.03,
        "cpu_burst_period1": 5, "cpu_burst_period2": 15, "cpu_burst_period3": 3.5,
        "cpu_burst_amp": 1.0,
        "mem_min": 72, "mem_max": 92, "swap_min": 8, "swap_max": 40,
        "disk_min": 68, "disk_max": 86,
        "net_min": 1048576, "net_max": 5242880,
        "conn_min": 220, "conn_max": 850,
        "proc_min": 120, "proc_max": 260
    }
}


class VirtualAgent:
    def __init__(self, config: dict):
        self.config = config
        self.identity = config.get("client_uuid") or config.get("name", "node")
        self.node_seed = self._hash_str(str(self.identity)) or 0.5
        self.usable = self._calc_usable()

    def _hash_str(self, s: str) -> float:
        h = 0
        for ch in s:
            h = (h * 31 + ord(ch)) & 0xffffffff
            if h > 0x7fffffff:
                h -= 0x100000000
        return abs(h) / 2147483647

    def _profile(self) -> dict:
        return PROFILE_DEFAULTS.get(self.config.get("load_profile"), PROFILE_DEFAULTS["mid"])

    def _mb(self, key: str, fallback: int, allow_zero: bool = False) -> int:
        try:
            v = float(self.config.get(key, fallback))
            if not (allow_zero and v >= 0 or v > 0):
                return fallback
            return int(v)
        except (ValueError, TypeError):
            return fallback

    def _calc_usable(self) -> dict:
        ram_total_mb = self._mb("ram_total", 1024)
        disk_total_mb = self._mb("disk_total", 10240)
        ram_base = round(80 + min(ram_total_mb * 0.05, 80))
        disk_base = round(2048 + min(disk_total_mb * 0.03, 2048))
        return {
            "ram": ram_total_mb * MB,
            "disk": disk_total_mb * MB,
            "swap": self._mb("swap_total", 0, True) * MB,
            "ramBaseMB": ram_base,
            "diskBaseMB": disk_base,
        }

    def _num(self, key: str) -> float:
        try:
            v = self.config.get(key)
            if v is not None:
                f = float(v)
                if math.isfinite(f):
                    return f
            return float(self._profile().get(key, 0))
        except (ValueError, TypeError):
            return float(self._profile().get(key, 0))

    def _range(self, min_key: str, max_key: str, limit: float = float("inf")):
        mn = self._num(min_key)
        mx = self._num(max_key)
        mn = max(0, min(limit, mn))
        mx = max(0, min(limit, mx))
        if mx < mn:
            mn, mx = mx, mn
        return mn, mx

    def _wave(self, t: float, size: float, shift: float = 0) -> float:
        return (math.sin(t / size + shift + self.node_seed * 2 * math.pi) + 1) / 2

    def _pulse(self, t: float, period: float, width: float, shift: float = 0) -> float:
        phase = ((((t + shift) % period) + period) % period) / period
        distance = min(phase, 1 - phase)
        return self._clamp(1 - distance / max(width, 0.01), 0, 1)

    def _roll(self, *parts) -> float:
        raw = "|".join(str(p) for p in (self.identity, *parts)).encode()
        return int.from_bytes(hashlib.blake2s(raw, digest_size=8).digest(), "big") / 0xffffffffffffffff

    def _cpu_target(self, name: str, profile: dict, bucket: int) -> float:
        roll = self._roll("cpu-target", name, bucket) * 100
        seen = 0
        ranges = profile["ranges"]
        lo, hi = ranges[-1][0], ranges[-1][1]
        for lo, hi, weight in ranges:
            seen += weight
            if roll <= seen:
                break
        return lo + (hi - lo) * self._roll("cpu-value", name, bucket)

    def _cpu_value(self, t: float) -> float:
        name = self.config.get("load_profile")
        profile = CPU_PROFILES.get(name, CPU_PROFILES["mid"])
        name = name if name in CPU_PROFILES else "mid"
        lo, hi = profile["cadence"]
        cadence = lo + (hi - lo) * self._roll("cpu-cadence")
        bucket = math.floor(t / cadence)
        phase = (t / cadence) - bucket
        previous = self._cpu_target(name, profile, bucket - 1)
        current = self._cpu_target(name, profile, bucket)
        chase = self._clamp(phase * (1 + profile["chase"]), 0, 1)
        jitter = (self._wave(t, 1.7, 5.3) - 0.5) * 2 * profile["jitter"]
        return self._clamp(previous + (current - previous) * chase + jitter, 0, 100)

    @staticmethod
    def _clamp(value: float, mn: float, mx: float) -> float:
        return max(mn, min(mx, value))

    def _uptime(self, now_sec: float) -> int:
        try:
            boot_time = float(self.config.get("boot_time") or 0)
        except (ValueError, TypeError):
            boot_time = 0
        if boot_time > 0:
            return max(0, int(now_sec - boot_time))
        try:
            base = float(self.config.get("uptime_base") or 86400)
        except (ValueError, TypeError):
            base = 86400
        try:
            created_at = self.config.get("created_at", "")
            if created_at:
                import datetime as _dt
                dt = _dt.datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
                return max(0, int(base + now_sec - dt.timestamp()))
        except Exception:
            pass
        return max(0, int(base))

    def generate_stats(self, tick: int = 0) -> dict:
        now = time.time()
        now_sec = int(now)
        t = now_sec + tick + int(self.node_seed * 997)

        now_dt = time.localtime(now)
        hour = now_dt.tm_hour + now_dt.tm_min / 60
        day_phase = 0.55 + 0.45 * math.sin(((hour - 7) / 24) * 2 * math.pi)
        active = self._clamp(
            0.12 + day_phase * 0.18 + self._wave(t, 600) * 0.22
            + self._wave(t, 55, 1.7) * 0.24 + self._wave(t, 8, 3.1) * 0.16, 0, 1
        )
        slow_active = self._clamp(
            0.15 + day_phase * 0.18 + self._wave(t, 600) * 0.25, 0, 1
        )

        cpu_burst_p1 = self._num("cpu_burst_period1")
        cpu_burst_p2 = self._num("cpu_burst_period2")
        cpu_burst_p3 = self._num("cpu_burst_period3")
        cpu_burst_amp = self._num("cpu_burst_amp")
        burst = max(
            self._pulse(t, cpu_burst_p1 + self.node_seed * 4, 0.22, self.node_seed * 11),
            self._pulse(t, cpu_burst_p2 + self.node_seed * 9, 0.16, 4.7),
            self._pulse(t, cpu_burst_p3 + self.node_seed * 3, 0.18, 8.3)
        )

        cpu = self._cpu_value(t)

        # Memory
        mem_min, mem_max = self._range("mem_min", "mem_max", 100)
        mem_span = max(0, mem_max - mem_min)
        mem = self._clamp(
            mem_min + mem_span * (
                0.18 + self.node_seed * 0.14 + self._wave(t, 1800, 2.2) * 0.34
                + self._wave(t, 5400, 3.5) * 0.14 + slow_active * 0.10
            ), 0, 100
        )
        ram_total_mb = self._mb("ram_total", 1024)
        mem_used_mb = ram_total_mb * mem / 100

        # Swap
        swap_total_mb = self._mb("swap_total", 0, True)
        if swap_total_mb <= 0:
            swap = 0
        else:
            swap_min2, swap_max2 = self._range("swap_min", "swap_max", 100)
            swap_span2 = max(1, swap_max2 - swap_min2)
            free_ram_mb = ram_total_mb - mem_used_mb
            swap_threshold = ram_total_mb * 0.25
            swap_pressure = self._clamp(1 - free_ram_mb / max(swap_threshold, 1), 0, 1)
            swap = self._clamp(
                swap_min2 + swap_span2 * (
                    swap_pressure * 0.65 + self._wave(t, 10800, 1.1) * 0.12
                    + slow_active * 0.05
                ), 0, 100
            )

        # Disk
        disk_min, disk_max = self._range("disk_min", "disk_max", 100)
        disk_span = max(0, disk_max - disk_min)
        disk_growth = ((int(t / 3600) + int(self.node_seed * 100)) % 720) / 720
        disk = self._clamp(
            disk_min + disk_span * (
                0.12 + self.node_seed * 0.58 + disk_growth * 0.22
                + self._wave(t, 7200, 0.7) * 0.06
            ), 0, 100
        )
        disk_total_mb = self._mb("disk_total", 10240)

        # Network
        net_min, net_max = self._range("net_min", "net_max")
        net_span = max(0, net_max - net_min)
        net_activity = self._clamp(active * 0.25 + (cpu / 100) * 0.62 + burst * 0.22, 0, 1)
        net_base = net_min + net_span * net_activity
        up = max(0, int(net_base * (0.20 + self.node_seed * 0.22)
                        * (0.72 + self._wave(t, 5.5, 1.3) * 0.70)))
        down = max(0, int(net_base * (0.55 + self.node_seed * 0.28)
                          * (0.72 + self._wave(t, 6.2, 2.4) * 0.70)))

        uptime = self._uptime(now_sec)
        avg_speed = (net_min + net_max) / 2
        total_up = int(uptime * avg_speed * (0.28 + self.node_seed * 0.12))
        total_down = int(uptime * avg_speed * (0.55 + self.node_seed * 0.18))

        # Connections
        conn_min, conn_max = self._range("conn_min", "conn_max")
        conn_span = max(1, conn_max - conn_min)
        conn = round(self._clamp(
            conn_min + conn_span * (slow_active * 0.80 + self._wave(t, 120, 1.5) * 0.10)
            + burst * 1.5, 0, max(conn_max * 1.15, conn_min)
        ))
        conn_udp = round(conn * (0.04 + self.node_seed * 0.12))

        # Process count
        proc_min, proc_max = self._range("proc_min", "proc_max")
        proc_span = max(1, proc_max - proc_min)
        proc = round(self._clamp(
            proc_min + proc_span * (
                0.32 + self.node_seed * 0.14 + slow_active * 0.14
                + self._wave(t, 7200, 2.0) * 0.08
            ), 1, max(proc_max * 1.10, proc_min)
        ))

        # Temperature
        cpu_thermal = self._clamp(
            cpu * 0.55 + slow_active * 20 + self._wave(t, 120, 0.8) * 20, 0, 100
        )
        temp = round(34 + cpu_thermal * 0.42 + self.node_seed * 5, 1)

        # Load averages
        cores = int(self.config.get("cpu_cores", 2))
        load1 = round(cpu / 100 * cores, 2)
        load5 = round(
            self._clamp(cpu * 0.55 + self._wave(t, 300, 0.5) * 25
                        + slow_active * 20, 0, 100) / 100 * cores, 2
        )
        load15 = round(
            self._clamp(cpu * 0.35 + self._wave(t, 900, 1.2) * 25
                        + slow_active * 30, 0, 100) / 100 * cores, 2
        )

        return {
            "cpu": round(cpu, 1), "mem": round(mem, 1), "swap": round(swap, 1),
            "disk": round(disk, 1), "up": up, "down": down,
            "totalUp": total_up, "totalDown": total_down,
            "conn": conn, "connUdp": conn_udp, "proc": proc,
            "uptime": uptime, "temp": temp,
            "load1": load1, "load5": load5, "load15": load15
        }
