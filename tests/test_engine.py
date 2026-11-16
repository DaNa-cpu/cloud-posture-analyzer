from cloud_analyzer.engine import run_scan
from cloud_analyzer.models import Resource, S3_BUCKET
from cloud_analyzer.rules import RULES_BY_ID


def test_s3_public_bucket_risk_depends_on_criticality():
    rule = RULES_BY_ID["S3-001"]

    low_criticality = Resource(
        id="bucket-low",
        type=S3_BUCKET,
        name="test-bucket-low",
        attributes={
            "public": True,
        },
        criticality=1,
    )

    high_criticality = Resource(
        id="bucket-high",
        type=S3_BUCKET,
        name="test-bucket-high",
        attributes={
            "public": True,
        },
        criticality=5,
    )

    low_findings = run_scan([low_criticality], [rule])
    high_findings = run_scan([high_criticality], [rule])

    assert len(low_findings) == 1
    assert len(high_findings) == 1

    low_finding = low_findings[0]
    high_finding = high_findings[0]

    assert low_finding.risk_score == 25
    assert high_finding.risk_score == 125
    assert high_finding.risk_score > low_finding.risk_score