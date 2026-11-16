
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
