from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

S3_BUCKET = "s3_bucket"
IAM_POLICY = "iam_policy"
SECURITY_GROUP = "security_group"
ACCOUNT = "account"

@dataclass(frozen=True)
class Resource:
    id: str
    type: str
    name: str
    attributes: dict
    criticality: int = 3
    source: str = "aws-config"

@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    resource_type: str
    severity: int
    exposure: int
    description: str
    remediation: str
    evaluate: Callable[[Resource], Optional[str]]

@dataclass
class Finding:
    rule_id: str
    title: str
    resource_id: str
    resource_type: str
    resource_name: str
    severity: int
    exposure: int
    criticality: int
    risk_score: int
    risk_label: str
    evidence: str
    description: str
    remediation: str
    source: str
    iso27001: list[str] = field(default_factory=list)
    soc2: list[str] = field(default_factory=list)
    control_rationale: str = field(default_factory=str)

    def to_dict(self) -> dict:
        return asdict(self)