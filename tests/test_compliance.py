from cloud_analyzer.rules import RULES
from cloud_analyzer.compliance import for_rule, load_controls


def test_every_rule_has_compliance_mapping():
    for rule in RULES:
        mapping = for_rule(rule.id)

        assert mapping["iso27001"]
        assert mapping["soc2"]
        assert isinstance(mapping["rationale"], str)
        assert mapping["rationale"].strip()


def test_every_mapped_control_exists_in_frameworks():
    frameworks = load_controls()["frameworks"]
    mappings = load_controls()["rules"]

    for rule_id, mapping in mappings.items():
        assert rule_id in [rule.id for rule in RULES]

        for control in mapping["iso27001"]:
            assert control in frameworks["iso27001"]

        for control in mapping["soc2"]:
            assert control in frameworks["soc2"]


def test_unknown_rule_raises_key_error():
    import pytest

    with pytest.raises(KeyError):
        for_rule("UNKNOWN-999")
