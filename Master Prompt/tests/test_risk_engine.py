from app.scanners.risk_engine import merge_risk


def test_risk_scoring():
    result = merge_risk(10, ["low"], [], {})
    assert result.verdict == "SAFE"
    assert result.score == 10
