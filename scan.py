
import argparse
import sys
from pathlib import Path

from cloud_analyzer.adapter import load_environment
from cloud_analyzer.engine import run_scan


PROJECT_ROOT = Path(__file__).resolve().parent
DEMO_FILE = PROJECT_ROOT / "fixtures" / "sample_env.json"


def display_findings(findings):
    """Display security findings in the terminal."""

    if not findings:
        print("No security findings detected.")
        return

    print(f"\nFound {len(findings)} security finding(s).\n")

    for index, finding in enumerate(findings, start=1):
        print("=" * 70)
        print(f"Finding #{index}")
        print(f"Rule:        {finding.rule_id} - {finding.title}")
        print(f"Resource:    {finding.resource_name}")
        print(f"Resource ID: {finding.resource_id}")
        print(f"Type:        {finding.resource_type}")
        print(f"Evidence:    {finding.evidence}")
        print(f"Remediation: {finding.remediation}")
        print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze cloud resources for security misconfigurations."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Exit with code 1 if a finding reaches this risk level.",
    )

    input_group = parser.add_mutually_exclusive_group()

    input_group.add_argument(
        "-i",
        "--input",
        help="Path to the JSON environment fixture.",
    )

    input_group.add_argument(
        "--demo",
        action="store_true",
        help="Run scanner against sample environment.",
    )

    args = parser.parse_args()

    if args.demo:
        input_path = DEMO_FILE
    elif args.input:
        input_path = Path(args.input)
    else:
        parser.error(
            "Provide an input file with --input or use --demo."
        )

    try:
        resources = load_environment(input_path)
        findings = run_scan(resources)

    except (OSError, ValueError, TypeError, KeyError) as error:
        print(
            f"Error: Could not load or analyze input: {error}",
            file=sys.stderr,
        )
        return 2

    display_findings(findings)

    if args.fail_on != "none":
        severity_order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        threshold = severity_order[args.fail_on]

        if any(
            severity_order[finding.risk_label.lower()] >= threshold
            for finding in findings
        ):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
