from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTROLS_FILE = PROJECT_ROOT / "mappings" / "controls.yaml"


def load_controls():
    """Load compliance mappings from the YAML file."""

    with CONTROLS_FILE.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError("Invalid controls.yaml structure.")

    return data


CONTROLS = load_controls()


def for_rule(rule_id):
    """Return compliance controls associated with a rule."""

    try:
        mapping = CONTROLS["rules"][rule_id]
    except KeyError:
        raise KeyError(
            f"No compliance mapping found for rule: {rule_id}"
        ) from None

    return {
        "iso27001": list(mapping["iso27001"]),
        "soc2": list(mapping["soc2"]),
        "rationale": mapping["rationale"],
    }
