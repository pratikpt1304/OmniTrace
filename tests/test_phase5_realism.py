"""
tests/test_phase5_realism.py
============================
Unit tests for Phase 5: Noise, Decoys, Realism, and Packaging.
Verifies:
  - Synthetic graph seeding generates background noise, benign cycles, and shared kiosks.
  - Benchmarks module executes without error and reports timings.
  - Dockerfile and docker-compose.yml exist and contain correct configurations.
  - Vendored frontend assets exist on disk in static/vendor/.
  - Frontend app.js contains zero alert() calls.
"""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from data.fraud_generator import seed_fraud_dataset
from benchmarks.multihop import create_sqlite_benchmark_db, benchmark_sqlite_recursive_cte


def test_seed_dataset_creates_noise_and_decoys():
    """Verify seed_fraud_dataset seeds decoys and noise accounts."""
    mock_graph = MagicMock()
    res = seed_fraud_dataset(graph=mock_graph)

    assert res["status"] == "success"
    scenarios = res["scenarios_seeded"]
    assert any("Decoy: Legitimate Corporate" in s for s in scenarios)
    assert any("Decoy: Legitimate Branch Kiosk" in s for s in scenarios)
    assert any("Background Retail Accounts" in s for s in scenarios)
    # Ensure query was called multiple times for each scenario
    assert mock_graph.query.call_count >= 5


def test_benchmark_sqlite_recursive_cte():
    """Verify multihop benchmark executes cleanly."""
    conn = create_sqlite_benchmark_db(chain_length=3)
    latency = benchmark_sqlite_recursive_cte(conn, start_id="ACC_0")
    assert isinstance(latency, float)
    assert latency >= 0.0


def test_packaging_and_docker_files():
    """Verify Dockerfile, docker-compose.yml, and CI workflow exist and are valid."""
    root = Path(__file__).resolve().parent.parent
    dockerfile = root / "Dockerfile"
    docker_compose = root / "docker-compose.yml"
    ci_workflow = root / ".github" / "workflows" / "test.yml"
    vendored_vis = root / "static" / "vendor" / "vis-network.min.js"

    assert dockerfile.exists(), "Dockerfile is missing"
    assert "falkordb" in docker_compose.read_text(encoding="utf-8")
    if ci_workflow.exists():
        assert "pytest" in ci_workflow.read_text(encoding="utf-8")
    assert vendored_vis.exists(), "Vendored vis-network.min.js is missing"
    assert vendored_vis.stat().st_size > 100000, "Vendored vis-network file appears truncated"


def test_frontend_zero_browser_alerts():
    """Verify app.js uses toast notifications and zero alert() calls."""
    root = Path(__file__).resolve().parent.parent
    app_js = (root / "static" / "app.js").read_text(encoding="utf-8")
    import re
    assert not re.search(r"\balert\(", app_js), "Found forbidden alert() call in static/app.js"
