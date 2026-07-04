import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import agent as agent_module
from agent import VirtualAgent
from reporters.cfmonitor import CFMonitorReporter
from routes.nodes import _random_uptime_base

DAY = 86400


def with_fixed_time(fn):
    original_time = agent_module.time.time
    original_localtime = agent_module.time.localtime
    fixed = 1700000000
    try:
        agent_module.time.time = lambda: fixed
        agent_module.time.localtime = lambda now=None: original_localtime(fixed if now is None else now)
        return fn()
    finally:
        agent_module.time.time = original_time
        agent_module.time.localtime = original_localtime


def sample(profile):
    return with_fixed_time(lambda: [VirtualAgent({
        "name": "node-" + profile,
        "load_profile": profile,
        "ram_total": 2048,
        "swap_total": 512,
        "disk_total": 20480,
        "uptime_base": 7 * DAY,
    }).generate_stats(i)["cpu"] for i in range(180)])


def test_cfmonitor_uses_official_total_traffic_fields():
    report = CFMonitorReporter({
        "name": "traffic",
        "cfmonitor_server": "https://example.com",
        "cfmonitor_token": "token",
        "ram_total": 1024,
        "disk_total": 10240,
        "uptime_base": 3 * DAY,
    }).build_report(1700000000)
    assert report["net_total_up"] > 0
    assert report["net_total_down"] > 0
    assert "net_total_in" not in report
    assert "net_total_out" not in report


def test_total_traffic_tracks_uptime_and_speed():
    def totals(uptime_days, net_min, net_max):
        return VirtualAgent({
            "name": f"traffic-{uptime_days}-{net_max}",
            "load_profile": "mid",
            "ram_total": 1024,
            "disk_total": 10240,
            "uptime_base": uptime_days * DAY,
            "net_min": net_min,
            "net_max": net_max,
        }).generate_stats(0)

    one_day = totals(1, 100_000, 200_000)
    ten_days = totals(10, 100_000, 200_000)
    fast = totals(1, 1_000_000, 2_000_000)
    assert ten_days["totalUp"] > one_day["totalUp"] * 5
    assert ten_days["totalDown"] > one_day["totalDown"] * 5
    assert fast["totalUp"] > one_day["totalUp"] * 5
    assert fast["totalDown"] > one_day["totalDown"] * 5


def test_new_nodes_randomize_uptime_between_1_and_30_days():
    values = [_random_uptime_base() for _ in range(200)]
    assert min(values) >= DAY
    assert max(values) <= 30 * DAY
    assert any(v > 7 * DAY for v in values)
    html = open("static/index.html", encoding="utf-8").read()
    assert "uptime_base:0" in html
    assert "(f.uptime_base||0)" in html


def test_cpu_presets_overlap_and_increase_by_profile():
    assert "cpu_min REAL DEFAULT 0.0" in open("db.py", encoding="utf-8").read()
    text = open("static/js/data.js", encoding="utf-8").read()
    values = [tuple(map(float, m)) for m in re.findall(r"(?:low|mid|high): \{ cpu_min: ([0-9.]+), cpu_max: ([0-9.]+),", text)]
    assert values == [(0, 40), (20, 75), (55, 95)]
    assert values[0][1] > values[1][0]
    assert values[1][1] > values[2][0]


def test_cpu_changes_are_profile_specific_and_visible():
    low, mid, high = sample("low"), sample("mid"), sample("high")
    low_span = max(low) - min(low)
    mid_span = max(mid) - min(mid)
    high_span = max(high) - min(high)
    assert min(low) >= 0 and min(mid) >= 0 and min(high) >= 0
    assert low_span >= 20
    assert mid_span >= 40
    assert high_span >= 55
    assert low_span < mid_span < high_span


def test_memory_swap_disk_keep_base_usage_and_move_slowly():
    def collect():
        a = VirtualAgent({
            "name": "stable-resources",
            "load_profile": "high",
            "ram_total": 2048,
            "swap_total": 512,
            "disk_total": 20480,
            "uptime_base": 7 * DAY,
        })
        return a, [a.generate_stats(i) for i in range(180)]

    agent, stats = with_fixed_time(collect)
    mem_used = [agent.usable["ram"] * s["mem"] / 100 for s in stats]
    disk_used = [agent.usable["disk"] * s["disk"] / 100 for s in stats]
    assert min(mem_used) > agent.usable["ramBaseMB"] * 1048576
    assert min(disk_used) > agent.usable["diskBaseMB"] * 1048576
    assert max(s["mem"] for s in stats) - min(s["mem"] for s in stats) < 8
    assert max(s["swap"] for s in stats) - min(s["swap"] for s in stats) < 5
    assert max(s["disk"] for s in stats) - min(s["disk"] for s in stats) < 2


def test_memory_and_disk_percentages_stay_inside_configured_ranges():
    def collect():
        a = VirtualAgent({
            "name": "bounded-resources",
            "load_profile": "mid",
            "ram_total": 1024,
            "swap_total": 512,
            "disk_total": 10240,
            "mem_min": 36.8,
            "mem_max": 39.8,
            "disk_min": 35.1,
            "disk_max": 35.3,
            "uptime_base": 7 * DAY,
        })
        return [a.generate_stats(i) for i in range(180)]

    stats = with_fixed_time(collect)
    assert all(36.8 <= s["mem"] <= 39.8 for s in stats)
    assert all(35.1 <= s["disk"] <= 35.3 for s in stats)


if __name__ == "__main__":
    test_cfmonitor_uses_official_total_traffic_fields()
    test_total_traffic_tracks_uptime_and_speed()
    test_new_nodes_randomize_uptime_between_1_and_30_days()
    test_cpu_presets_overlap_and_increase_by_profile()
    test_cpu_changes_are_profile_specific_and_visible()
    test_memory_swap_disk_keep_base_usage_and_move_slowly()
    test_memory_and_disk_percentages_stay_inside_configured_ranges()
