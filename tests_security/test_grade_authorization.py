
import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


# Supplied positive example — does not count as assessed work.
def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


# Additional legitimate operation.
def test_admin_can_update_grade(client):
    login(client, "admin1", "adminpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SRS", "grade": 17},
    )

    assert response.status_code == 200
    assert api.find_grade(1002, "SRS")["grade"] == 17


# An unauthenticated client must not modify grades.
def test_anonymous_user_cannot_update_grade(client):
    original = api.find_grade(1001, "SRS")["grade"]

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 19},
    )

    assert response.status_code == 401
    assert api.find_grade(1001, "SRS")["grade"] == original


# Students may read permitted grades, but not update them.
def test_student_cannot_update_own_grade(client):
    login(client, "alice", "alicepw")
    original = api.find_grade(1001, "SRS")["grade"]

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 19},
    )

    assert response.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == original


# A professor must not update a course outside their assignment.
def test_professor_cannot_update_unassigned_course(client):
    login(client, "prof_srs", "profpw")
    original = api.find_grade(1001, "SSD")["grade"]

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 19},
    )

    assert response.status_code == 403
    assert api.find_grade(1001, "SSD")["grade"] == original
