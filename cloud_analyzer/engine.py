from cloud_analyzer.models import Finding, Resource, Rule
from cloud_analyzer.compliance import for_rule
from cloud_analyzer.rules import RULES
from cloud_analyzer.risk import risk_score, risk_label

def run_scan(
    resources: list[Resource],
    rules: list[Rule] = RULES,
) -> list[Finding]:
    """Evaluate security rules against normalized resources."""

    findings = []

    for resource in resources:
        for rule in rules:

            if rule.resource_type != resource.type:
                continue

            evidence = rule.evaluate(resource)

            if evidence is None:
                continue

            score = risk_score(
                rule.severity,
                rule.exposure,
                resource.criticality
            )
            
            label = risk_label(score)

            compliance = for_rule(rule.id)

            finding = Finding(
                rule_id=rule.id,
                title=rule.title,
                resource_id=resource.id,
                resource_type=resource.type,
                resource_name=resource.name,
                severity=rule.severity,
                exposure=rule.exposure,
                criticality=resource.criticality,
                risk_score=score,
                risk_label=label,
                evidence=evidence,
                description=rule.description,
                remediation=rule.remediation,
                source=resource.source,
                iso27001=compliance["iso27001"],
                soc2=compliance["soc2"],
                control_rationale=compliance["rationale"],
            )

            findings.append(finding)

    # Sortare deterministă:
    # risc descrescător, rule_id, numele resursei.
    findings.sort(
        key=lambda finding: (
            -finding.risk_score,
            finding.rule_id,
            finding.resource_name,
        )
    )

    return findings
