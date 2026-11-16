import json

from cloud_analyzer.models import Finding
from cloud_analyzer.reports import (
    build_summary,
    render_json,
    render_html,
)


def make_finding(resource_name="test-bucket", score=100, label="Critical"):
    return Finding(
        rule_id="S3-001",
        title="Public S3 Bucket",
        resource_id="bucket-001",
        resource_type="s3_bucket",
        resource_name=resource_name,
        severity=5,
        exposure=5,
        criticality=4,
        risk_score=score,
        risk_label=label,
        evidence="Bucket allows public access.",
        description="Public access can expose data.",
        remediation="Remove public access.",
        source="aws-config",
        iso27001=["A.8.3"],
        soc2=["CC6.1"],
        control_rationale="Review access restrictions.",
    )


def test_build_summary():
    findings = [
        make_finding(score=100, label="Critical"),
        make_finding(score=60, label="High"),
        make_finding(score=20, label="Medium"),
    ]

    summary = build_summary(findings)

    assert summary["total_findings"] == 3
    assert summary["by_label"]["Critical"] == 1
    assert summary["by_label"]["High"] == 1
    assert summary["by_label"]["Medium"] == 1
    assert summary["by_label"]["Low"] == 0
    assert summary["max_risk"] == 100


def test_empty_summary():
    summary = build_summary([])

    assert summary["total_findings"] == 0
    assert summary["max_risk"] == 0
    assert sum(summary["by_label"].values()) == 0


def test_json_report_is_valid():
    findings = [make_finding()]

    report = render_json(findings)
    data = json.loads(report)

    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["rule_id"] == "S3-001"


def test_html_escapes_resource_name():
    findings = [
        make_finding(resource_name="<script>alert(1)</script>")
    ]

    html = render_html(findings)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
