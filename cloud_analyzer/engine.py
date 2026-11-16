
from cloud_analyzer.models import Finding, Resource, Rule
from cloud_analyzer.rules import RULES


def run_scan(
    resources: list[Resource],
    rules: list[Rule] = RULES,
) -> list[Finding]:
    """
    Evaluate security rules against normalized resources.

    Returns a list of findings sorted deterministically.
    """
    findings = []

    for resource in resources:
        for rule in rules:
            # Only evaluate rules that match the resource type.
            if rule.resource_type != resource.type:
                continue

            evidence = rule.evaluate(resource)

            # None means the resource passed this rule.
            if evidence is None:
                continue

            finding = Finding(
                rule_id=rule.id,
                title=rule.title,
                resource_id=resource.id,
                resource_type=resource.type,
                resource_name=resource.name,
                severity=rule.severity,
                exposure=rule.exposure,
                criticality=resource.criticality,
                risk_score=0,
                risk_label="",
                evidence=evidence,
                description=rule.description,
                remediation=rule.remediation,
                source=resource.source,
            )

            findings.append(finding)

    # Sort by risk score (descending), rule ID, and resource name.
    findings.sort(
        key=lambda finding: (
            -finding.risk_score,
            finding.rule_id,
            finding.resource_name,
        )
    )

    return findings
