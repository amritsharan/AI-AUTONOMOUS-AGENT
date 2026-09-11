"""
Integration tests for QuantumShield AI REST APIs using TestClient.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as tc:
        yield tc


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "QuantumShield AI"


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "docs" in data


def test_quantum_algorithms(client):
    response = client.get("/api/quantum/algorithms")
    assert response.status_code == 200
    data = response.json()
    assert "algorithms" in data
    assert "RSA" in data["algorithms"]
    assert "AES-256" in data["algorithms"]


def test_quantum_pqc_standards(client):
    response = client.get("/api/quantum/pqc-standards")
    assert response.status_code == 200
    data = response.json()
    assert "standards" in data


def test_quantum_shor_assessment(client):
    response = client.post("/api/quantum/shor-assessment?algorithm=RSA&key_size=2048")
    assert response.status_code == 200
    data = response.json()
    assert data["shor_applicable"] is True
    assert data["quantum_resistant"] is False


def test_quantum_grover_assessment(client):
    response = client.post("/api/quantum/grover-assessment?algorithm=AES-256&key_size=256")
    assert response.status_code == 200
    data = response.json()
    assert data["is_sufficient"] is True


def test_quantum_shor_demo(client):
    response = client.post("/api/quantum/shor-demo", json={"N": 15})
    assert response.status_code == 200
    data = response.json()
    assert data["N"] == 15
    assert data["success"] is True


def test_quantum_grover_demo(client):
    response = client.post("/api/quantum/grover-demo", json={"search_space_size": 4, "marked_item": 3})
    assert response.status_code == 200
    data = response.json()
    assert data["item_found"] is True
    assert data["found_item"] == 3
