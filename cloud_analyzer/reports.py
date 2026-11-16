import json
from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def build_summary(findings):
    """Build aggregate statistics for a scan."""
    labels = ("Critical", "High", "Medium", "Low")
    counts = Counter(finding.risk_label for finding in findings)

    return {
        "total_findings": len(findings),
        "by_label": {
            label: counts.get(label, 0)
            for label in labels
        },
        "max_risk": max(
            (finding.risk_score for finding in findings),
            default=0,
        ),
    }


def render_json(findings):
    """Serialize findings and summary as JSON."""
    data = {
        "summary": build_summary(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_html(findings):
    """Render findings using an autoescaping Jinja2 template."""
    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
    )

    template = environment.get_template("report.html.j2")

    return template.render(
        summary=build_summary(findings),
        findings=findings,
    )