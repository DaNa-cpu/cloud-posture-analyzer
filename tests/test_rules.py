import pytest

from cloud_analyzer.models import (
    Resource,
    S3_BUCKET,
    IAM_POLICY,
    SECURITY_GROUP,
    ACCOUNT,
)

from cloud_analyzer.rules import RULES_BY_ID

def make_resource(resource_type, attributes, name="test-resource"):
    """Create resource object for testing."""
    return Resource(
        id=name,
        type=resource_type,
        name=name,
        attributes=attributes,
    )

@pytest.mark.parametrize(
    "rule_id, resource, expected",
    [
        # S3-001: public bucket
        (
            "S3-001",
            make_resource(S3_BUCKET, {"public": True},),
            True,
        ),
        (
            "S3-001",
            make_resource(S3_BUCKET, {"public": False},),
            False,
        ),
        # S3-002: unencrypted bucket
        (
            "S3-002",
            make_resource(S3_BUCKET, {"encryption_algorithm": None},),
            True,
        ),
        (
            "S3-002",       
        make_resource(S3_BUCKET, {"encryption_algorithm": "AES256"},),
            False,
        ),
        # S3-003: versioning disabled
        (
            "S3-003",
            make_resource(S3_BUCKET, {"versioning_status": "Disabled"},),
            True,
        ),
        (
            "S3-003",
            make_resource(S3_BUCKET, {"versioning_status": "Enabled"},),
            False,
        ),
        # IAM-001: full admin policy
        (
            "IAM-001",
            make_resource(IAM_POLICY, {"allows_full_admin": True},),
            True,
        ),
        (
            "IAM-001",
            make_resource(IAM_POLICY, {"allows_full_admin": False},),
            False,      
        ),
        # IAM-002: policy with no statements
        (
            "IAM-002",
            make_resource(IAM_POLICY, {"root_mfa_enabled": False},),        
            True,   
        ),
        (
            "IAM-002",
            make_resource(IAM_POLICY, {"root_mfa_enabled": True},),
            False,
        ),
        # NET-001: public SSH access
        (
            "NET-001",
            make_resource(
                SECURITY_GROUP, 
                {
                    "world_ingress": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr": "0.0.0.0/0",
                        }
                    ]
                },
            ),
            True,
        ),
        (
            "NET-001",
            make_resource(
                SECURITY_GROUP, 
                {
                    "world_ingress": [
                        {
                            "protocol": "tcp",
                            "from_port": 80,
                            "to_port": 80,
                            "cidr": "0.0.0.0/0"
                        }
                    ]
                },
            ),
            False,
        ),
        # NET-002: public RDP access
        (
            "NET-002",
            make_resource(
                SECURITY_GROUP, 
                {
                    "world_ingress": [
                        {
                            "protocol": "tcp",
                            "from_port": 3389,
                            "to_port": 3389,
                            "cidr": "::/0"
                        }
                    ]
                },
            ),
            True,
        ),
        (
            "NET-002",
            make_resource(
                SECURITY_GROUP, 
                {
                    "world_ingress": [
                        {
                            "protocol": "tcp",
                            "from_port": 443,
                            "to_port": 443,
                            "cidr": "0.0.0.0/0"
                        }
                    ]
                },
            ),
            False,
        ),
        # LOG-001: CloudTrail logging disabled
        (
            "LOG-001",
            make_resource(
                ACCOUNT, 
                {
                    "cloudtrail_trails": [
                        {"name":"main-trail", "is_logging": False}]
                },
            ),
            True,
        ),
        (
            "LOG-001",
            make_resource(
                ACCOUNT, 
                {
                    "cloudtrail_trails": [
                        {"name":"main-trail", "is_logging": True}]
                },
            ),
            False,
        ),
    ],
)
def test_rule_evaluation(rule_id, resource, expected):
    """Check that each rule identifies insecure and secure resources."""
    result = RULES_BY_ID[rule_id].evaluate(resource)

    if expected:
        assert isinstance(result, str)
        assert result
    else:
        assert result is None

@pytest.mark.parametrize(
    "rule_id, resource, expected",
    [
        # A port range containing 22 must trigger SSH detection.
        (
            "NET-001",
            make_resource(
                SECURITY_GROUP,
                {
                    "world_ingress": [
                        {
                            "protocol": "tcp",
                            "from_port": 20,
                            "to_port": 30,
                            "cidr": "0.0.0.0/0",
                        }
                    ]
                },
            ),
            True,
        ),

        # UDP on port 22 must not trigger SSH detection.
        (
            "NET-001",
            make_resource(
                SECURITY_GROUP,
                {
                    "world_ingress": [
                        {
                            "protocol": "udp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr": "0.0.0.0/0",
                        }
                    ]
                },
            ),
            False,
        ),

        # The "all" protocol must trigger SSH detection.
        (
            "NET-001",
            make_resource(
                SECURITY_GROUP,
                {
                    "world_ingress": [
                        {
                            "protocol": "all",
                            "from_port": 0,
                            "to_port": 65535,
                            "cidr": "0.0.0.0/0",
                        }
                    ]
                },
            ),
            True,
        ),

        # The "all" protocol must also trigger RDP detection.
        (
            "NET-002",
            make_resource(
                SECURITY_GROUP,
                {
                    "world_ingress": [
                        {
                            "protocol": "all",
                            "from_port": 0,
                            "to_port": 65535,
                            "cidr": "::/0",
                        }
                    ]
                },
            ),
            True,
        ),

        # Unknown MFA status must not trigger a finding.
        (
            "IAM-002",
            make_resource(ACCOUNT, {"root_mfa_enabled": None}),
            False,
        ),

        # Unknown CloudTrail status must not trigger a finding.
        (
            "LOG-001",
            make_resource(ACCOUNT, {"cloudtrail_trails": None}),
            False,
        ),

        # An empty CloudTrail list must trigger a finding.
        (
            "LOG-001",
            make_resource(ACCOUNT, {"cloudtrail_trails": []}),
            True,
        ),
    ],
)
def test_rule_edge_cases(rule_id, resource, expected):
    """Check boundary conditions and special cases."""
    result = RULES_BY_ID[rule_id].evaluate(resource)

    if expected:
        assert isinstance(result, str)
        assert result
    else:
        assert result is None