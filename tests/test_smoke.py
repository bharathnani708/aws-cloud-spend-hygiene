"""Offline smoke tests: no AWS credentials needed (boto3 is stubbed)."""
import os, sys, types
from datetime import datetime, timedelta, timezone

for name in ("boto3", "botocore", "botocore.config"):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["botocore.config"].Config = lambda **k: None
sys.modules["boto3"].client = lambda *a, **k: None
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ["USE_PRICING_API"] = "false"

import lambda_function as L  # noqa: E402


def sample(region="us-east-1"):
    created = datetime.now(timezone.utc) - timedelta(days=300)
    f = L.finding(region, "EBS snapshot", "snap-0123456789abcdef0", created=created, size_gb=100,
                  confidence="MEDIUM", evidence="Source volume still exists; snapshot is old",
                  cost=5.0, basis="100 GB x $0.05/GB-mo", rec="Review and delete")
    f.pop("_cur_ids"); f.pop("_cur_extra")
    return f


def test_parse_regions():
    assert L.parse_regions("all") is None
    assert L.parse_regions("") is None
    assert L.parse_regions(["US-East-1", "us-east-1", "ca-central-1"]) == ["us-east-1", "ca-central-1"]


def test_email_builds_without_labels_or_signature():
    subject, text, html, total, high = L.build_email([sample()], [], [], 1, "p/", "123456789012", ["us-east-1"], 17)
    assert "Account 123456789012" in subject and "1 resource" in subject
    assert "Created" in html and total == 5.0 and high == 0.0


def test_price_fallback_is_labelled():
    usd, src = L.rate("us-east-1", "snapshot_gb")
    assert usd > 0 and src.startswith("approx")


if __name__ == "__main__":
    for n, fn in list(globals().items()):
        if n.startswith("test_"):
            fn(); print("ok", n)
