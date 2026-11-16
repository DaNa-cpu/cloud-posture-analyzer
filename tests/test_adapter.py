import json

import pytest

from cloud_analyzer.adapter import load_environment, normalize
from cloud_analyzer.models import ACCOUNT, IAM_POLICY, S3_BUCKET, SECURITY_GROUP


ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"

PUBLIC_ACL = {"Grants": [{"Grantee": {"Type": "Group", "URI": ALL_USERS}}]}
PUBLIC_POLICY = {
    "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    ]
}


def one(raw, resource_type):
    """Return the single resource of the given type."""
    found = [r for r in normalize(raw) if r.type == resource_type]
    assert len(found) == 1
    return found[0]


def bucket(**fields):
    return one({"s3_buckets": [{"Name": "b", **fields}]}, S3_BUCKET)


# --- S3: public access -------------------------------------------------


def test_public_acl_without_block_is_public():
    assert bucket(Acl=PUBLIC_ACL).attributes["public"] is True


def test_public_acl_is_ignored_when_ignore_public_acls_is_on():
    resource = bucket(
        Acl=PUBLIC_ACL,
        PublicAccessBlockConfiguration={"IgnorePublicAcls": True},
    )
    assert resource.attributes["public"] is False


def test_public_policy_without_block_is_public():
    assert bucket(Policy=PUBLIC_POLICY).attributes["public"] is True


def test_public_policy_is_ignored_when_restrict_public_buckets_is_on():
    resource = bucket(
        Policy=PUBLIC_POLICY,
        PublicAccessBlockConfiguration={"RestrictPublicBuckets": True},
    )
    assert resource.attributes["public"] is False


def test_partial_block_with_nothing_public_is_not_public():
    resource = bucket(
        PublicAccessBlockConfiguration={"BlockPublicAcls": True}
    )
    assert resource.attributes["public"] is False


def test_deny_statement_is_not_public():
    policy = {"Statement": [{"Effect": "Deny", "Principal": "*"}]}
    assert bucket(Policy=policy).attributes["public"] is False


@pytest.mark.parametrize(
    "principal",
    ["*", {"AWS": "*"}, {"AWS": ["*"]}],
)
def test_all_forms_of_public_principal_are_detected(principal):
    policy = {"Statement": [{"Effect": "Allow", "Principal": principal}]}
    assert bucket(Policy=policy).attributes["public"] is True


def test_specific_principal_is_not_public():
    principal = {"AWS": "arn:aws:iam::123456789012:root"}
    policy = {"Statement": [{"Effect": "Allow", "Principal": principal}]}
    assert bucket(Policy=policy).attributes["public"] is False


def test_policy_given_as_json_string_is_parsed():
    # `aws s3api get-bucket-policy` returns the policy as a JSON string.
    assert bucket(Policy=json.dumps(PUBLIC_POLICY)).attributes["public"] is True


def test_policy_with_invalid_json_raises_value_error():
    with pytest.raises(ValueError):
        bucket(Policy="{not json")


# --- S3: encryption and versioning -----------------------------------------


def test_encryption_algorithm_is_read_from_first_rule():
    resource = bucket(
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
            ]
        }
    )
    assert resource.attributes["encryption_algorithm"] == "aws:kms"


def test_missing_encryption_is_none():
    assert bucket().attributes["encryption_algorithm"] is None
    assert (
        bucket(ServerSideEncryptionConfiguration=None).attributes[
            "encryption_algorithm"
        ]
        is None
    )


def test_versioning_defaults_to_disabled():
    assert bucket().attributes["versioning_status"] == "Disabled"
    assert bucket(Versioning={}).attributes["versioning_status"] == "Disabled"


def test_versioning_status_is_kept():
    resource = bucket(Versioning={"Status": "Suspended"})
    assert resource.attributes["versioning_status"] == "Suspended"


# --- criticality -----------------------------------------------------------


@pytest.mark.parametrize(
    "tag_value, expected",
    [("low", 1), ("medium", 3), ("high", 4), ("critical", 5), ("CRITICAL", 5)],
)
def test_criticality_tag_values(tag_value, expected):
    tags = [{"Key": "criticality", "Value": tag_value}]
    assert bucket(Tags=tags).criticality == expected


def test_missing_and_unknown_criticality_use_the_same_default():
    unknown = [{"Key": "criticality", "Value": "banana"}]
    assert bucket().criticality == 3
    assert bucket(Tags=unknown).criticality == 3


# --- IAM -------------------------------------------------------------------


def policy(statement):
    raw = {
        "iam_policies": [
            {"PolicyName": "p", "PolicyDocument": {"Statement": statement}}
        ]
    }
    return one(raw, IAM_POLICY)


def test_allow_star_on_star_is_full_admin():
    statement = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    assert policy(statement).attributes["allows_full_admin"] is True


def test_single_statement_object_is_accepted():
    statement = {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}
    assert policy(statement).attributes["allows_full_admin"] is True


def test_service_wildcard_is_not_full_admin():
    statement = [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    assert policy(statement).attributes["allows_full_admin"] is False


def test_star_on_specific_resource_is_not_full_admin():
    statement = [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]
    assert policy(statement).attributes["allows_full_admin"] is False


def test_deny_star_is_not_full_admin():
    statement = [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
    assert policy(statement).attributes["allows_full_admin"] is False


# --- security groups -------------------------------------------------------


def group(permission):
    raw = {"security_groups": [{"GroupId": "sg-1", "IpPermissions": [permission]}]}
    return one(raw, SECURITY_GROUP)


def test_world_open_ipv4_rule_is_recorded():
    resource = group(
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    )
    assert resource.attributes["world_ingress"] == [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}
    ]


def test_world_open_ipv6_rule_is_recorded():
    resource = group(
        {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
    )
    assert resource.attributes["world_ingress"][0]["cidr"] == "::/0"


def test_private_cidr_is_not_world_open():
    resource = group(
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        }
    )
    assert resource.attributes["world_ingress"] == []


def test_all_traffic_protocol_becomes_all_ports():
    resource = group({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    assert resource.attributes["world_ingress"] == [
        {"protocol": "all", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"}
    ]


# --- account (root MFA and CloudTrail) ----------------------------------


def test_root_mfa_values():
    off = {"account_summary": {"SummaryMap": {"AccountMFAEnabled": 0}}}
    on = {"account_summary": {"SummaryMap": {"AccountMFAEnabled": 1}}}
    assert one(off, ACCOUNT).attributes["root_mfa_enabled"] is False
    assert one(on, ACCOUNT).attributes["root_mfa_enabled"] is True


def test_unknown_root_mfa_is_none():
    raw = {"cloud_trails": []}
    assert one(raw, ACCOUNT).attributes["root_mfa_enabled"] is None


def test_missing_cloudtrail_section_is_unknown_not_empty():
    raw = {"account_summary": {"SummaryMap": {"AccountMFAEnabled": 1}}}
    assert one(raw, ACCOUNT).attributes["cloudtrail_trails"] is None


def test_empty_cloudtrail_section_is_an_empty_list():
    assert one({"cloud_trails": []}, ACCOUNT).attributes["cloudtrail_trails"] == []


def test_cloudtrail_status_is_read():
    raw = {
        "cloud_trails": [
            {"Name": "t", "IsMultiRegionTrail": True, "TrailStatus": {"IsLogging": False}}
        ]
    }
    trails = one(raw, ACCOUNT).attributes["cloudtrail_trails"]
    assert trails == [{"name": "t", "is_logging": False, "multi_region": True}]


# --- whole-input behavior ----------------------------------------------------


def test_empty_input_has_no_resources():
    assert normalize({}) == []


def test_non_object_input_is_rejected():
    with pytest.raises(ValueError):
        normalize([])


def test_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_environment(tmp_path / "missing.json")


def test_invalid_json_file_raises_value_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_environment(path)


def test_unknown_top_level_key_triggers_a_warning():
    # e.g. a typo: "cloudtrail_trails" instead of "cloud_trails"
    with pytest.warns(UserWarning, match="cloudtrail_trails"):
        normalize({"cloudtrail_trails": []})


def test_known_keys_do_not_trigger_a_warning(recwarn):
    normalize({"s3_buckets": [], "cloud_trails": []})
    assert len(recwarn) == 0
