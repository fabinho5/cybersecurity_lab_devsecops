
import pytest

import baseline_secure_coding_api as api


@pytest.fixture
def sample_files(tmp_path, monkeypatch):
    materials = tmp_path / "materials"
    materials.mkdir()

    allowed = materials / "allowed.txt"
    allowed.write_text("Public teaching material", encoding="utf-8")

    outside = tmp_path / "private.txt"
    outside.write_text("PRIVATE_TEST_MARKER", encoding="utf-8")

    monkeypatch.setattr(api, "MATERIALS_DIR", materials)

    return {"allowed": allowed, "outside": outside}


def login_student(client):
    response = client.post(
        "/login",
        data={"username": "alice", "password": "alicepw"},
        follow_redirects=True,
    )
    assert response.status_code == 200


# Legitimate download must remain functional.
def test_authenticated_user_can_download_material(client, sample_files):
    login_student(client)

    response = client.get("/files", query_string={"path": "allowed.txt"})

    assert response.status_code == 200
    assert response.data == b"Public teaching material"


# Protected materials must require authentication.
def test_anonymous_user_cannot_download_material(client, sample_files):
    response = client.get("/files", query_string={"path": "allowed.txt"})

    assert response.status_code == 401
    assert b"Public teaching material" not in response.data


# Parent-directory traversal must not disclose outside files.
def test_parent_directory_traversal_is_blocked(client, sample_files):
    login_student(client)

    response = client.get(
        "/files",
        query_string={"path": "../private.txt"},
    )

    assert 400 <= response.status_code < 500
    assert b"PRIVATE_TEST_MARKER" not in response.data


# Absolute paths must not bypass directory containment.
def test_absolute_path_escape_is_blocked(client, sample_files):
    login_student(client)

    response = client.get(
        "/files",
        query_string={"path": str(sample_files["outside"])},
    )

    assert 400 <= response.status_code < 500
    assert b"PRIVATE_TEST_MARKER" not in response.data
