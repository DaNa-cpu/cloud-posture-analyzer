
import json
from pathlib import Path

from cloud_analyzer.models import (
    Resource,
    S3_BUCKET,
    IAM_POLICY,
    SECURITY_GROUP,
    ACCOUNT,
)


def _as_list(value):
    """Convert a value into a list. None becomes an empty list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _tags(tags):
    """Convert AWS tags into a dictionary."""
    result = {}

    for tag in _as_list(tags):
        if not isinstance(tag, dict):
            continue

        key = tag.get("Key")
        value = tag.get("Value")

        if key is not None:
            result[key] = value

    return result


def _criticality(tags):
    """Convert the criticality tag into a numeric score."""
    value = str(tags.get("criticality", "medium")).lower()

    levels = {
        "low": 1,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    return levels.get(value, 3)


def _s3_bucket(bucket):
    """Normalize an S3 bucket."""

    tags = _tags(bucket.get("Tags"))
    public_reasons = []

    # 1. Check the bucket ACL.
    acl = bucket.get("Acl") or {}
    grants = _as_list(acl.get("Grants"))

    public_acl = False

    for grant in grants:
        if not isinstance(grant, dict):
            continue

        grantee = grant.get("Grantee") or {}
        uri = grantee.get("URI", "")

        if (
            uri.endswith("/groups/global/AllUsers")
            or uri.endswith("/groups/global/AuthenticatedUsers")
        ):
            public_acl = True
            break

    # 2. Check the bucket policy.
    policy = bucket.get("Policy") or {}
    statements = _as_list(policy.get("Statement"))

    public_policy = False

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        principal = statement.get("Principal")
        effect = statement.get("Effect")

        principal_is_public = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and principal.get("AWS") == "*"
            )
        )

        if effect == "Allow" and principal_is_public:
            public_policy = True
            break

    # 3. Check S3 Block Public Access settings.
    public_access_block = (
        bucket.get("PublicAccessBlockConfiguration") or {}
    )

    if public_acl and not public_access_block.get("IgnorePublicAcls", False):
        public_reasons.append("Public ACL")

    if public_policy and not public_access_block.get("RestrictPublicBuckets", False):
        public_reasons.append("Public bucket policy")

    # 4. Check encryption settings.
    encryption = bucket.get("ServerSideEncryptionConfiguration") or {}
    encryption_rules = _as_list(encryption.get("Rules"))

    encryption_algorithm = None

    if encryption_rules:
        first_rule = encryption_rules[0] or {}
        default_encryption = (
            first_rule.get("ApplyServerSideEncryptionByDefault") or {}
        )
        encryption_algorithm = default_encryption.get("SSEAlgorithm")

    # 5. Check bucket versioning.
    versioning = bucket.get("Versioning") or {}
    versioning_status = versioning.get("Status", "Disabled")

    return Resource(
        id=bucket.get("Name", "unknown-bucket"),
        type=S3_BUCKET,
        name=bucket.get("Name", "unknown-bucket"),
        attributes={
            "public": bool(public_reasons),
            "public_reasons": public_reasons,
            "encryption_algorithm": encryption_algorithm,
            "versioning_status": versioning_status,
            "public_access_block": public_access_block,
        },
        criticality=_criticality(tags),
    )


def _iam_policy(policy):
    """Normalize an IAM policy."""

    document = policy.get("PolicyDocument") or policy
    statements = _as_list(document.get("Statement"))

    allows_full_admin = False

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow":
            continue

        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))

        if "*" in actions and "*" in resources:
            allows_full_admin = True
            break

    name = (
        policy.get("PolicyName")
        or policy.get("name")
        or "unknown-policy"
    )

    return Resource(
        id=name,
        type=IAM_POLICY,
        name=name,
        attributes={
            "allows_full_admin": allows_full_admin,
        },
        criticality=_criticality(_tags(policy.get("Tags"))),
    )


def _security_group(group):
    """Normalize a Security Group and identify internet-accessible ingress rules."""

    world_ingress = []

    ip_permissions = _as_list(group.get("IpPermissions"))

    for permission in ip_permissions:
        if not isinstance(permission, dict):
            continue

        protocol = permission.get("IpProtocol", "unknown")

        if protocol == "-1":
            protocol_name = "all"
            from_port = 0
            to_port = 65535
        else:
            protocol_name = protocol
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

        # Check IPv4 ranges.
        ipv4_ranges = _as_list(permission.get("IpRanges"))

        for ip_range in ipv4_ranges:
            if not isinstance(ip_range, dict):
                continue

            cidr = ip_range.get("CidrIp")

            if cidr == "0.0.0.0/0":
                world_ingress.append({
                    "protocol": protocol_name,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                })

        # Check IPv6 ranges.
        ipv6_ranges = _as_list(permission.get("Ipv6Ranges"))

        for ip_range in ipv6_ranges:
            if not isinstance(ip_range, dict):
                continue

            cidr = ip_range.get("CidrIpv6")

            if cidr == "::/0":
                world_ingress.append({
                    "protocol": protocol_name,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                })

    name = (
        group.get("GroupName")
        or group.get("GroupId")
        or "unknown-security-group"
    )

    return Resource(
        id=group.get("GroupId", name),
        type=SECURITY_GROUP,
        name=name,
        attributes={
            "world_ingress": world_ingress,
        },
        criticality=_criticality(_tags(group.get("Tags"))),
    )


def _account(raw):
    """Normalize AWS account and CloudTrail information."""

    account_summary = raw.get("account_summary") or {}
    summary_map = account_summary.get("SummaryMap") or {}

    mfa_value = summary_map.get("AccountMFAEnabled")

    if mfa_value is None:
        root_mfa_enabled = None
    else:
        root_mfa_enabled = bool(mfa_value)

    cloudtrail_data = []

    for trail in _as_list(raw.get("cloud_trails")):
        if not isinstance(trail, dict):
            continue

        trail_status = trail.get("TrailStatus") or {}

        cloudtrail_data.append({
            "name": trail.get("Name", "unknown-trail"),
            "is_logging": trail_status.get("IsLogging"),
            "multi_region": trail.get("IsMultiRegionTrail"),
        })

    return Resource(
        id=raw.get("account_id", "unknown-account"),
        type=ACCOUNT,
        name=raw.get("account_id", "AWS Account"),
        attributes={
            "root_mfa_enabled": root_mfa_enabled,
            "cloudtrail_trails": (
                cloudtrail_data
                if "cloudtrail_trails" in raw
                else None
            ),
        },
        criticality=5,
    )


def normalize(raw):
    """Convert raw AWS data into normalized Resource objects."""

    if not isinstance(raw, dict):
        raise ValueError("Environment data must be a JSON object.")

    resources = []

    # Normalize S3 buckets.
    for bucket in _as_list(raw.get("s3_buckets")):
        if isinstance(bucket, dict):
            resources.append(_s3_bucket(bucket))

    # Normalize IAM policies.
    for policy in _as_list(raw.get("iam_policies")):
        if isinstance(policy, dict):
            resources.append(_iam_policy(policy))

    # Normalize Security Groups.
    for group in _as_list(raw.get("security_groups")):
        if isinstance(group, dict):
            resources.append(_security_group(group))

    # Add an Account resource if account data is available.
    if "account_summary" in raw or "cloudtrail_trails" in raw:
        resources.append(_account(raw))

    return resources


def load_environment(path):
    """Load a JSON file and normalize its resources."""

    file_path = Path(path)

    try:
        with file_path.open("r", encoding="utf-8") as file:
            raw_data = json.load(file)

    except FileNotFoundError:
        raise FileNotFoundError(
            f"Environment file not found: {file_path}"
        )

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {file_path}: {error}"
        ) from error

    return normalize(raw_data)
