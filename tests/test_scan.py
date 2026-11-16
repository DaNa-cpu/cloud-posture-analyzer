
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCAN_SCRIPT = PROJECT_ROOT / "scan.py"
FIXTURES = PROJECT_ROOT / "fixtures"


def test_fail_on_critical_sample():
    result = subprocess.run(
        [
            sys.executable,
            str(SCAN_SCRIPT),
            "--input",
            str(FIXTURES / "sample_env.json"),
            "--fail-on",
            "critical",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1


def test_fail_on_low_clean():
    result = subprocess.run(
        [
            sys.executable,
            str(SCAN_SCRIPT),
            "--input",
            str(FIXTURES / "clean_env.json"),
            "--fail-on",
            "low",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0


def run_scan_cli(*args):
    return subprocess.run(
        [sys.executable, str(SCAN_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )


def test_demo_json_goes_to_stdout_and_does_not_write_report_html(tmp_path):
    report = PROJECT_ROOT / "reports" / "report.html"
    existed_before = report.exists()

    result = run_scan_cli("--demo", "--format", "json")

    assert result.returncode == 0
    assert '"findings"' in result.stdout
    assert report.exists() == existed_before


def test_demo_html_is_written_to_the_requested_file(tmp_path):
    output = tmp_path / "demo.html"

    result = run_scan_cli("--demo", "--output", str(output))

    assert result.returncode == 0
    assert "Cloud" in output.read_text(encoding="utf-8")


def test_demo_shows_a_public_bucket_finding():
    result = run_scan_cli("--demo", "--format", "json")
    rule_ids = {finding["rule_id"] for finding in json.loads(result.stdout)["findings"]}
    assert "S3-001" in rule_ids


def test_missing_input_file_exits_with_code_2():
    assert run_scan_cli("--input", "does-not-exist.json").returncode == 2


def test_invalid_policy_exits_with_code_2_not_a_traceback(tmp_path):
    env = tmp_path / "bad_policy.json"
    env.write_text(
        json.dumps({"s3_buckets": [{"Name": "b", "Policy": "{not json"}]}),
        encoding="utf-8",
    )

    result = run_scan_cli("--input", str(env))

    assert result.returncode == 2
    assert "Traceback" not in result.stderr
