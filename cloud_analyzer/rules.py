from cloud_analyzer.models import (
    Rule,
    S3_BUCKET,
    IAM_POLICY,
    SECURITY_GROUP,
    ACCOUNT,
)

# S3 rules

def _s3_public_bucket(resource):
    """Detect an S3 bucket that allows public access."""
    if resource.attributes.get("public") is True:
        return "Bucket allows public access."

    return None


def _s3_missing_encryption(resource):
    """Detect an S3 bucket without server-side encryption."""
    if resource.attributes.get("encryption_algorithm") is None:
        return "Bucket does not have server-side encryption configured."

    return None


def _s3_versioning_disabled(resource):
    """Detect an S3 bucket with versioning disabled."""
    if resource.attributes.get("versioning_status") != "Enabled":
        return "Bucket versioning is not enabled."

    return None

# IAM rules

def _iam_full_admin(resource):
    """Detect an IAM policy with full administrative permissions."""
    if resource.attributes.get("allows_full_admin") is True:
        return "IAM policy allows all actions on all resources."

    return None


def _root_mfa_disabled(resource):
    """Detect an AWS root account without MFA."""
    if resource.attributes.get("root_mfa_enabled") is False:
        return "AWS root account does not have MFA enabled."

    return None

# Network rules

def _world_open_port(resource, port, label):
    """Detect a sensitive port exposed to the entire internet."""

    world_cidrs = {"0.0.0.0/0", "::/0"}

    ingress_rules = resource.attributes.get("world_ingress") or []

    for rule in ingress_rules:
        protocol = rule.get("protocol")
        cidr = rule.get("cidr")
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")

        if protocol not in {"tcp", "all"}:
            continue

        if cidr not in world_cidrs:
            continue

        if not isinstance(from_port, int) or not isinstance(to_port, int):
            continue

        if from_port <= port <= to_port:
            return (
                f"{label} port {port} is exposed to the internet "
                f"({cidr}, protocol: {protocol})."
            )

    return None

def _public_ssh(resource):
    """Detect SSH access exposed to the internet."""
    return _world_open_port(resource, 22, "SSH")


def _public_rdp(resource):
    """Detect RDP access exposed to the internet."""
    return _world_open_port(resource, 3389, "RDP")

# Logging rules

def _cloudtrail_not_logging(resource):
    """Detect missing or inactive CloudTrail logging."""

    trails = resource.attributes.get("cloudtrail_trails")

    # None means that the CloudTrail information is unknown.
    if trails is None:
        return None

    # An empty list means that no trails were found.
    if not trails:
        return "No CloudTrail trails are configured."

    # At least one active trail is sufficient for this rule.
    if not any(
        isinstance(trail, dict) and trail.get("is_logging") is True
        for trail in trails
    ):
        return "No CloudTrail trail is currently logging."

    return None

# Rule definition

RULES = [
    Rule(
        id="S3-001",
        title="Public S3 Bucket",
        resource_type=S3_BUCKET,
        severity=5,
        exposure=5,
        description=(
            "A publicly accessible S3 bucket can expose sensitive data, "
            "affecting confidentiality under the CIA triad."
        ),
        remediation=(
            "Review the bucket ACL and policy. Remove unintended public "
            "access and enable the appropriate S3 Block Public Access settings."
        ),
        evaluate=_s3_public_bucket,
    ),

    Rule(
        id="S3-002",
        title="S3 Bucket Without Encryption",
        resource_type=S3_BUCKET,
        severity=4,
        exposure=2,
        description=(
            "Without server-side encryption, stored data may be exposed "
            "if storage access is compromised, affecting confidentiality."
        ),
        remediation=(
            "Enable default server-side encryption using SSE-S3 or SSE-KMS."
        ),
        evaluate=_s3_missing_encryption,
    ),

    Rule(
        id="S3-003",
        title="S3 Bucket Versioning Disabled",
        resource_type=S3_BUCKET,
        severity=3,
        exposure=1,
        description=(
            "Without versioning, accidental deletion or overwriting can "
            "reduce data availability and integrity."
        ),
        remediation=(
            "Enable versioning on the S3 bucket to preserve object versions."
        ),
        evaluate=_s3_versioning_disabled,
    ),

    Rule(
        id="IAM-001",
        title="IAM Policy Allows Full Administrative Access",
        resource_type=IAM_POLICY,
        severity=5,
        exposure=3,
        description=(
            "Full administrative permissions increase the impact of "
            "credential compromise, threatening confidentiality, integrity, "
            "and availability."
        ),
        remediation=(
            "Replace wildcard permissions with specific actions and resources "
            "following the principle of least privilege."
        ),
        evaluate=_iam_full_admin,
    ),

    Rule(
        id="IAM-002",
        title="Root Account MFA Disabled",
        resource_type=ACCOUNT,
        severity=4,
        exposure=4,
        description=(
            "Without MFA, a compromised root password can give an attacker "
            "control over the account, threatening all three CIA properties."
        ),
        remediation=(
            "Enable multi-factor authentication for the AWS root user."
        ),
        evaluate=_root_mfa_disabled,
    ),

    Rule(
        id="NET-001",
        title="SSH Exposed to the Internet",
        resource_type=SECURITY_GROUP,
        severity=5,
        exposure=5,
        description=(
            "Public SSH access increases the risk of unauthorized access "
            "and system compromise, threatening confidentiality and integrity."
        ),
        remediation=(
            "Restrict inbound SSH access to trusted IP addresses or use "
            "AWS Systems Manager Session Manager."
        ),
        evaluate=_public_ssh,
    ),

    Rule(
        id="NET-002",
        title="RDP Exposed to the Internet",
        resource_type=SECURITY_GROUP,
        severity=5,
        exposure=5,
        description=(
            "Public RDP access increases the risk of brute-force attacks "
            "and unauthorized remote control, threatening all three CIA properties."
        ),
        remediation=(
            "Restrict inbound RDP access to trusted IP addresses or use "
            "a secure remote access solution."
        ),
        evaluate=_public_rdp,
    ),

    Rule(
        id="LOG-001",
        title="CloudTrail Logging Disabled",
        resource_type=ACCOUNT,
        severity=4,
        exposure=3,
        description=(
            "Without active CloudTrail logging, suspicious activity may go "
            "undetected, reducing accountability and incident investigation capabilities."
        ),
        remediation=(
            "Create a CloudTrail trail if none exists, enable logging, "
            "and deliver logs to a protected S3 bucket."
        ),
        evaluate=_cloudtrail_not_logging,
    ),
]

# Rule lookup

RULES_BY_ID = {
    rule.id: rule
    for rule in RULES
}
