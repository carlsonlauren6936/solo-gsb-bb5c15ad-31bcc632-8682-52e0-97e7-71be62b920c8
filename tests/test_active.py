"""End-to-end tests for the publish-pointer endpoints (/api/active)."""

from __future__ import annotations

import os
import tempfile
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-active-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _activate(client: TestClient, analysis_id: str, expected_revision: int):
    return client.post(
        "/api/active/activate",
        json={"analysis_id": analysis_id, "expected_revision": expected_revision},
    )


# ---------------------------------------------------------------------------
def test_initial_state(client: TestClient) -> None:
    r = client.get("/api/active")
    assert r.status_code == 200
    assert r.json() == {"revision": 0, "active_id": None, "updated_at": None}

    h = client.get("/api/active/history")
    assert h.status_code == 200
    assert h.json() == {"total": 0, "activations": []}


def test_activate_then_pointer_and_history(client: TestClient) -> None:
    a = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}], name="v1")
    b = _save(client, [{"cidr": "10.0.0.0/8", "action": "deny"}], name="v2")

    r = _activate(client, a, 0)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["revision"] == 1
    assert body["active_id"] == a
    assert body["previous_id"] is None
    assert body["activated_at"]

    state = client.get("/api/active").json()
    assert state["revision"] == 1
    assert state["active_id"] == a
    assert state["updated_at"] == body["activated_at"]

    r = _activate(client, b, 1)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["revision"] == 2
    assert body["active_id"] == b
    assert body["previous_id"] == a

    h = client.get("/api/active/history").json()
    assert h["total"] == 2
    newest, oldest = h["activations"]  # newest first
    assert newest["revision"] == 2
    assert newest["active_id"] == b
    assert newest["previous_id"] == a
    assert newest["activated_at"]
    assert oldest["revision"] == 1
    assert oldest["active_id"] == a
    assert oldest["previous_id"] is None

    # Pagination mirrors /api/analyses.
    page = client.get("/api/active/history", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 2
    assert len(page["activations"]) == 1
    assert page["activations"][0]["revision"] == 1


def test_stale_revision_conflict_returns_409_and_current_state(client: TestClient) -> None:
    a = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])
    b = _save(client, [{"cidr": "10.1.0.0/16", "action": "deny"}])

    assert _activate(client, a, 0).status_code == 200

    # A caller holding the stale revision 0 must not overwrite the pointer.
    r = _activate(client, b, 0)
    assert r.status_code == 409
    body = r.json()
    assert body["error"] == "revision_conflict"
    assert body["current"]["revision"] == 1
    assert body["current"]["active_id"] == a

    # The pointer and the history are untouched by the failed attempt.
    state = client.get("/api/active").json()
    assert state["revision"] == 1
    assert state["active_id"] == a
    assert client.get("/api/active/history").json()["total"] == 1

    # Retrying with the fresh revision succeeds.
    r = _activate(client, b, 1)
    assert r.status_code == 200
    assert r.json()["revision"] == 2
    assert r.json()["active_id"] == b


def test_activate_unknown_or_unsaved_analysis(client: TestClient) -> None:
    r = _activate(client, "an_0000000000000000", 0)
    assert r.status_code == 404
    assert "not found" in r.json()["detail"]

    # An unsaved (save:false) analysis has no stored version to point at.
    unsaved = client.post(
        "/api/analyze",
        json={"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}], "save": False},
    ).json()
    assert unsaved["persisted"] is False
    r = _activate(client, unsaved["id"], 0)
    assert r.status_code == 404

    # Failed activations leave the pointer untouched.
    assert client.get("/api/active").json() == {
        "revision": 0,
        "active_id": None,
        "updated_at": None,
    }
    assert client.get("/api/active/history").json()["total"] == 0


def test_activate_request_validation(client: TestClient) -> None:
    # Missing expected_revision
    assert client.post("/api/active/activate", json={"analysis_id": "an_x"}).status_code == 422
    # Negative revision
    r = _activate(client, "an_x", -1)
    assert r.status_code == 422
    # Empty analysis_id
    assert (
        client.post(
            "/api/active/activate", json={"analysis_id": "  ", "expected_revision": 0}
        ).status_code
        == 422
    )
    # Unknown field
    assert (
        client.post(
            "/api/active/activate",
            json={"analysis_id": "an_x", "expected_revision": 0, "extra": 1},
        ).status_code
        == 422
    )


def test_concurrent_activations_do_not_overwrite(client: TestClient) -> None:
    ids = [
        _save(client, [{"cidr": f"10.{i}.0.0/16", "action": "permit"}]) for i in range(4)
    ]

    # Four publishers race on the same expected revision at the DB layer
    # (each call opens its own connection, exactly like concurrent requests).
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda aid: db.activate_analysis(aid, 0), ids))

    winners = [o for o in outcomes if o["outcome"] == "activated"]
    losers = [o for o in outcomes if o["outcome"] == "conflict"]
    assert len(winners) == 1
    assert len(losers) == 3
    for loser in losers:
        assert loser["current"]["revision"] == 1

    state = client.get("/api/active").json()
    assert state["revision"] == 1
    assert state["active_id"] == winners[0]["state"]["active_id"]
    assert client.get("/api/active/history").json()["total"] == 1
