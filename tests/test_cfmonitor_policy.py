import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from reporters.cfmonitor import CFMonitorReporter
from scheduler import _cfmonitor_fingerprint


def make_reporter():
    return CFMonitorReporter({
        "name": "test",
        "cfmonitor_server": "https://example.com",
        "cfmonitor_token": "token",
        "ram_total": 512,
        "disk_total": 1024,
        "load_profile": "mid",
    })


def test_policy_intervals():
    reporter = make_reporter()
    reporter._apply_policy({
        "type": "policy",
        "mode": "active",
        "sample_interval_sec": 3,
        "report_interval_sec": 3,
        "report_now": True,
        "viewer_count": 1,
    })
    assert reporter.sample_interval_sec() == 3
    assert reporter.upload_interval_sec() == 3
    assert reporter.force_timer_reset is True
    assert reporter.policy["report_now"] is True

    reporter._apply_policy({
        "type": "policy",
        "mode": "idle",
        "sample_interval_sec": 120,
        "report_interval_sec": 120,
        "viewer_count": 0,
    })
    assert reporter.sample_interval_sec() == 120
    assert reporter.upload_interval_sec() == 120


def test_cfmonitor_fingerprint_changes_on_token_edit():
    node = {"id": 1, "cfmonitor_server": "https://a", "cfmonitor_token": "old", "name": "n"}
    changed = dict(node, cfmonitor_token="new")
    assert _cfmonitor_fingerprint(node) != _cfmonitor_fingerprint(changed)


def test_cfmonitor_reports_detailed_region_in_report_and_basic_info():
    reporter = CFMonitorReporter({
        "name": "geo",
        "cfmonitor_server": "https://example.com",
        "cfmonitor_token": "token",
        "fake_ip": "1.3.29.85",
        "region": "CN",
    })
    report = reporter.build_report(1700000000)
    assert report["ipv4"] == "1.3.29.85"
    assert report["region"] == "China, CN"
    assert report["basic_info"]["ipv4"] == "1.3.29.85"
    assert report["basic_info"]["region"] == "China, CN"


if __name__ == "__main__":
    test_policy_intervals()
    test_cfmonitor_fingerprint_changes_on_token_edit()
    test_cfmonitor_reports_detailed_region_in_report_and_basic_info()
