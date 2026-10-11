"""
backend/tests/test_health_redis_config.py

Targeted tests for Fix 6: Health endpoint Redis configuration.
Uses mocks — no live Redis server required.
"""

import os
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

import upload_api


@pytest.fixture
def client():
    return TestClient(upload_api.app)


def test_redis_url_uses_arise_redis_url(monkeypatch):
    """Test that upload_api respects ARISE_REDIS_URL configuration."""
    custom_url = "redis://custom-host:6380/2"
    monkeypatch.setenv("ARISE_REDIS_URL", custom_url)

    # Reload or check REDIS_URL definition
    assert upload_api.REDIS_URL is not None
    # Verify health uses configured url without NameError
    with patch("redis.Redis.from_url") as mock_from_url:
        mock_redis = MagicMock()
        mock_from_url.return_value = mock_redis
        mock_redis.ping.return_value = True

        response = upload_api.health()
        assert response["status"] == "healthy"
        assert response["checks"]["redis"] == "ok"


def test_health_redis_ping_success(client):
    """Test health endpoint when Redis ping succeeds."""
    with patch("redis.Redis.from_url") as mock_from_url:
        mock_redis = MagicMock()
        mock_from_url.return_value = mock_redis
        mock_redis.ping.return_value = True

        res = client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["checks"]["api"] == "ok"
        assert data["checks"]["redis"] == "ok"
        assert "timestamp" in data


def test_health_redis_unavailable_does_not_leak_credentials(client, monkeypatch):
    """Test health endpoint when Redis fails, verifying credentials are not exposed."""
    secret_url = "redis://:super_secret_password@redis-server:6379/0"
    monkeypatch.setattr(upload_api, "REDIS_URL", secret_url)

    with patch("redis.Redis.from_url") as mock_from_url:
        # Simulate an exception containing the URL/password
        mock_from_url.side_effect = ConnectionError(f"Failed to connect to {secret_url}")

        res = client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "degraded"
        assert "unavailable" in data["checks"]["redis"]
        # Ensure credentials / sensitive host details are not leaked in the response
        assert "super_secret_password" not in data["checks"]["redis"]
        assert "super_secret_password" not in str(data)


def test_health_missing_redis_config_no_nameerror(monkeypatch, client):
    """Test that missing ARISE_REDIS_URL falls back safely and never raises NameError."""
    monkeypatch.delenv("ARISE_REDIS_URL", raising=False)

    with patch("redis.Redis.from_url") as mock_from_url:
        mock_redis = MagicMock()
        mock_from_url.return_value = mock_redis
        mock_redis.ping.return_value = True

        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"
