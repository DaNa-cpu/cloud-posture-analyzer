import pytest

from cloud_analyzer.risk import risk_score, risk_label


def test_risk_score():
    assert risk_score(5, 5, 5) == 125


@pytest.mark.parametrize(
    "severity, exposure, criticality",
    [
        (0, 3, 3),
        (6, 3, 3),
        (3, 0, 3),
        (3, 6, 3),
        (3, 3, 0),
        (3, 3, 6),
        (True, 3, 3),
    ],
)
def test_invalid_risk_values(severity, exposure, criticality):
    with pytest.raises(ValueError):
        risk_score(severity, exposure, criticality)


@pytest.mark.parametrize(
    "score, expected",
    [
        (80, "Critical"),
        (79, "High"),
        (45, "High"),
        (44, "Medium"),
        (15, "Medium"),
        (14, "Low"),
    ],
)
def test_risk_label_boundaries(score, expected):
    assert risk_label(score) == expected
