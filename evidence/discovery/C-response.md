# Static Security Review — Academic Services REST API

Reviewed file: `baseline_secure_coding_api.py` (159 lines)\
Review method: Static source inspection only\
Security baseline: R1–R7 supplied in the request\
Execution: None. No tests, external tools, or web searches were used.

## 1. Executive summary

The source contains multiple security weaknesses affecting authentication, authorization, input validation, file access, session integrity, and error handling.

The most significant risks are:

- Unauthenticated access to student profiles, grades, grade modifications, and teaching materials.
- Missing record-level and course-level authorization.
- Unrestricted grade updates, including invalid academic records.
- Path traversal allowing potential access to files outside the materials directory.
- A hardcoded session-signing secret.

These are static findings, not experimentally verified exploits. The severity assessments assume an attacker can reach the relevant HTTP endpoints.

## 2. Findings table

| ID  | Finding                                                               | Location                                                                                     | Severity | Confidence |
| --- | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | -------- | ---------- |
| F01 | Missing authentication on protected endpoints                         | `get_profile` 115–120; `get_grades` 122–126; `update_grade` 128–142; `download_file` 144–148 | Critical | High       |
| F02 | Insecure direct object reference in student profiles                  | `get_profile`, 115–120                                                                       | High     | High       |
| F03 | Missing grade ownership and course-level authorization                | `get_grades`, 122–126                                                                        | High     | High       |
| F04 | Unauthorized grade modification                                       | `update_grade`, 128–142                                                                      | Critical | High       |
| F05 | Missing grade-update schema, type, range, and reference validation    | `update_grade`, 130–140                                                                      | High     | High       |
| F06 | Directory traversal and unrestricted filesystem access                | `download_file`, 146–148                                                                     | Critical | High       |
| F07 | Unvalidated student identifiers and incorrect invalid-input responses | `get_profile` 117; `get_grades` 124–126                                                      | Medium   | High       |
| F08 | Internal error disclosure and incorrect HTTP error handling           | `handle_error`, 150–155                                                                      | Medium   | High       |
| F09 | Hardcoded session secret enables potential session forgery            | Application setup, 7–8; `login`, 91–94                                                       | High     | High\*     |
| F10 | Debug mode enabled on a network-facing development server             | Application startup, 158–159                                                                 | Medium\* | High       |

\*F09 depends on Flask's standard signed-cookie session behavior. F10's exploitability depends on how the application is launched and exposed.

All ten findings are grounded in the supplied source. F01–F08 concern direct violations of the specified requirements. F09 and F10 concern additional security weaknesses whose impact depends partly on framework behavior or deployment conditions.

## 3. Supporting explanations

### F01 — Missing authentication on protected endpoints

Demonstrated facts: The four protected endpoint handlers access application data without checking `flask.session`, authentication state, or the current user.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: An unauthenticated client can supply a student identifier, grade-update JSON body, or file path. The request reaches the corresponding handler and proceeds directly to data retrieval, modification, or file delivery.

Root cause: No authentication enforcement at the route or application level, violating R1.

Preconditions and impact: The API must be reachable. No valid account is required. Student records may be disclosed, grade records modified, and files downloaded.

Proposed test: Without logging in, request `/students/1001/profile`, `/grades/1001`, and `/files?path=srs-summary.txt`. Separately submit a valid grade update while unauthenticated. Each should return 401, and the update should leave stored data unchanged.

Uncertainty: The source shows no external authentication middleware. If an unmentioned reverse proxy enforces authentication, exposure could differ. Confidence: High for the application-level defect.

### F02 — Insecure direct object reference in student profiles

Demonstrated facts: `get_profile` converts the supplied `student_id` to an integer, looks it up in `STUDENT_PROFILES`, and returns the matching record without checking ownership or role.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: An authenticated student controls the URL parameter. For example, Alice (student 1001) can request `/students/1002/profile`, which retrieves Bob's profile.

Root cause: A valid identifier is treated as sufficient to retrieve a record. The handler does not enforce R2 or R3.

Preconditions and impact: A requester needs to know or guess a student identifier. Exposure includes the student's name, email address, and academic program.

Proposed test: Authenticate as Alice and request student 1002's profile; expect 403. Authenticate as `prof_srs` and request student 1001's profile; also expect 403. Administrator access should succeed.

Uncertainty: Student ownership and professor restrictions are explicitly defined, so no additional policy assumption is needed. Confidence: High.

### F03 — Missing grade ownership and course-level authorization

Demonstrated facts: `get_grades` filters the grade list only by the requested student identifier:

`row["student_id"] == sid`

There is no comparison with the requester's student identifier or assigned courses.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: Alice can request `/grades/1002` to read Bob's grades. Professor `prof_srs`, assigned only to SRS, can request `/grades/1001` and receive both Alice's SRS and SSD grades.

Root cause: Missing object ownership checks and course-based filtering. This violates R2, R3, and R4.

Preconditions and impact: Knowledge of another student's identifier is sufficient. Grade confidentiality can be compromised across students and courses.

Proposed test: Authenticate as Alice and request `/grades/1002`; expect 403. Authenticate as `prof_srs` and request `/grades/1001`; the response should contain only the SRS grade. A request producing no authorized records must be denied rather than returning unauthorized data.

Uncertainty: The specified policy unambiguously requires filtering. Confidence: High.

### F04 — Unauthorized grade modification

Demonstrated facts: `update_grade` accepts JSON fields, searches for the grade record, then either modifies the existing grade or appends a new record. No role, student ownership, or assigned-course check precedes mutation.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: The requester controls `student_id`, `course_id`, and `grade` in the POST body. Those values directly determine the grade record created or modified.

Root cause: Missing write authorization, violating R3 and R4, in addition to the authentication defect in F01.

Preconditions and impact: Any requester able to submit a valid JSON request can potentially alter academic grades, undermining academic-record integrity.

Proposed test: Authenticate as Alice and attempt to change her SRS grade; expect 403. Authenticate as `prof_srs` and attempt to modify an SSD grade; expect 403. An administrator should be able to perform a valid update. Verify the data remains unchanged after both denied requests.

Uncertainty: R2 grants students read access, while R3 grants update privileges to professors and administrators. The assessment assumes students have no grade-update privilege, consistent with that role model. Confidence: High.

### F05 — Missing grade-update input validation

Demonstrated facts: `update_grade` reads JSON fields directly and assigns their values without validating types, ranges, known courses, or student existence. Missing fields can raise exceptions.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: User-supplied JSON flows through `request.get_json()`, dictionary indexing, `find_grade()`, and then into `GRADES`.

Root cause: The update handler lacks the schema and domain validation required by R5.

Preconditions and impact: A requester who can reach the endpoint can introduce invalid grade values, nonexistent student identifiers, or unknown courses. Malformed payloads may also produce server errors.

Proposed test: Using isolated copies of the initial data, submit the following invalid payloads and verify that every request returns a client error without changing `GRADES`.

| Invalid input       | Example                                              | Expected reason for rejection        |
| ------------------- | ---------------------------------------------------- | ------------------------------------ |
| Grade above maximum | `{"student_id":1001,"course_id":"SRS","grade":25}`   | Grade exceeds 20                     |
| Boolean grade       | `{"student_id":1001,"course_id":"SRS","grade":true}` | Boolean is not a valid numeric grade |
| Unknown student     | `{"student_id":9999,"course_id":"SRS","grade":15}`   | Student does not exist               |
| Unknown course      | `{"student_id":1001,"course_id":"XYZ","grade":15}`   | Course is not SRS or SSD             |
| Missing field       | `{"student_id":1001,"grade":15}`                     | Required `course_id` missing         |

Uncertainty: R5 requires an existing student and known course but does not explicitly prohibit creating a previously absent student/course grade association. Therefore, the append behavior is not independently classified as a defect when both references and the grade value are valid. Confidence: High.

### F06 — Directory traversal and unrestricted filesystem access

Demonstrated facts: `download_file` takes the `path` query parameter, combines it with `MATERIALS_DIR`, and passes the resulting path directly to `flask.send_file`. It does not restrict the resolved target to the materials directory.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: The attacker controls `path`. Parent-directory segments such as `../` can cause the target to reference files outside `MATERIALS_DIR`; absolute paths can also override the intended base under standard `pathlib` semantics.

Root cause: No path-containment enforcement, violating R6.

Preconditions and impact: The targeted file must exist and be readable by the application process. The defect could expose application source, configuration, credentials, or other server-side information. Because the source contains the session secret and demonstration passwords, successful source disclosure could also facilitate other attacks.

Proposed test: Authenticate and request `/files?path=../baseline_secure_coding_api.py`. The expected secure result is a client error denying access outside the materials directory. Also confirm that `/files?path=secure-coding.txt` remains downloadable.

Uncertainty: The exact response depends on filesystem permissions and runtime path handling. The unsafe path construction is directly visible, but successful disclosure has not been executed. Confidence: High.

### F07 — Unvalidated student identifiers

Demonstrated facts: Both student lookup handlers call `int(student_id)` without validating the input first. The grade retrieval handler also returns an empty list for identifiers with no matching records.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: The attacker controls the URL segment. Noninteger strings such as `abc` reach `int()` and can raise `ValueError`. Zero and negative values can pass integer conversion but violate the positive-identifier requirement.

Root cause: Missing route parameter validation, violating R5 and contributing to R7 failures.

Preconditions and impact: No special privileges are needed. Malformed requests can cause inappropriate server-error responses; invalid identifiers may also receive responses inconsistent with the specified validation policy.

Proposed test: Request `/students/abc/profile`, `/grades/abc`, and `/grades/-1`. Each should receive an appropriate client error, not 500. Test zero and nonexistent identifiers as well. For a grade-list request with no permitted records, ensure R4's denial requirement is respected.

Uncertainty: The precise error status for a nonexistent but well-formed student identifier is not fully prescribed; 404 may be appropriate. Confidence: High.

### F08 — Internal error disclosure and incorrect error status codes

Demonstrated facts: The global exception handler includes `str(exc)` and the exception class name in its response and returns HTTP 500 for every exception it handles.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: Invalid identifiers, missing JSON fields, invalid request bodies, or missing file targets can produce exceptions. Those exceptions pass to the broad handler, which serializes exception information into the HTTP response.

Root cause: A generic exception handler is used without differentiating validation errors, authorization failures, HTTP exceptions, and actual server faults. This violates R7.

Preconditions and impact: Attackers can trigger malformed requests and potentially obtain exception details, including internal file paths in filesystem-related errors. Normal client errors may incorrectly become 500 responses.

Proposed test: Request a nonexistent route and send a malformed grade update. Confirm appropriate 4xx responses without Python exception names, internal file paths, or traceback details.

Uncertainty: Which exception messages contain sensitive paths depends on the failure and runtime. The direct inclusion of exception details is certain. Confidence: High.

### F09 — Hardcoded session secret

Demonstrated facts: The Flask `SECRET_KEY` is the constant string `"dev-secret-key"`. The login endpoint stores the username, role, student identifier, and course assignments in the session; `/me` reads those claims and checks for the presence of `"user"`.&#x20;

baseline_secure_coding_api.py

baseline_secure_coding_api.py



Attacker input and flow: Under standard Flask signed-cookie sessions, an attacker who knows the secret key can potentially construct a correctly signed cookie containing arbitrary session claims, which are then read by `/me`.

Root cause: A static, source-visible secret undermines the integrity of session authentication claims.

Preconditions and impact: The attacker needs knowledge of the signing key and the ability to supply a session cookie. If forged session claims are trusted for authorization, identity and role impersonation become possible. In the current code, `/me` is the directly observable consumer; the protected endpoints already lack authorization checks.

Proposed test: In an isolated test environment, create a session cookie signed with the configured key but containing an administrator identity without performing login. Check whether `/me` accepts those claims.

Uncertainty: This conclusion assumes Flask's standard client-side signed-session implementation and that an attacker obtains the hardcoded key. Confidence: High for secret exposure and predictable configuration; conditional for practical impersonation.

### F10 — Debug mode exposed through the application startup configuration

Demonstrated facts: The application starts with `debug=True` and binds to `0.0.0.0` when invoked directly.&#x20;

baseline_secure_coding_api.py



Attacker input and flow: If that development server is reachable remotely, a requester may reach routes that generate unhandled errors. Debug facilities may disclose additional implementation information.

Root cause: Debug functionality is enabled in a potentially network-accessible runtime configuration, creating a conditional R7 exposure.

Preconditions and impact: The application must be launched using the shown `app.run()` path and the relevant debug functionality must be reachable. The global exception handler may intercept many ordinary failures, reducing the externally observable debug surface.

Proposed test: In an isolated deployment configured as shown, trigger a controlled unhandled exception and inspect the HTTP response for debug diagnostics or interactive debugging functionality. No such functionality should be available to remote clients.

Uncertainty: There is no evidence about actual deployment or whether exceptions can escape the global handler. The configuration is confirmed, but remote exploitability is not. Confidence: High for the configuration finding; Medium for security impact.

## 4. Consolidated requirements assessment

| Requirement                 | Static assessment | Related findings            |
| --------------------------- | ----------------- | --------------------------- |
| R1 — Authentication         | Violated          | F01                         |
| R2 — Student privacy        | Violated          | F02, F03                    |
| R3 — Academic staff scope   | Violated          | F02, F03, F04               |
| R4 — Complete authorization | Violated          | F02, F03, F04               |
| R5 — Input validation       | Violated          | F05, F07                    |
| R6 — File access            | Violated          | F06                         |
| R7 — Error handling         | Violated          | F07, F08; F10 conditionally |

## 5. Review limitations and conclusions

The source establishes the missing checks and unsafe data flows, but it does not establish that these weaknesses have been exploited. The proposed tests are intended to distinguish source-level observations from confirmed runtime behavior.

The principal limitations are that no requests were executed, no deployment configuration beyond the provided source was examined, and no external access controls or runtime mitigations were assumed.

Priority for validation: F01, F04, and F06 first, because they permit unauthenticated access, unauthorized data modification, or potential filesystem disclosure. F02 and F03 then establish the record-level and course-level authorization boundaries. F05 should be validated independently for data integrity, followed by the session and error-handling findings.

The review identifies 10 potential security findings, including eight direct requirement-related defects and two additional conditional security concerns. No patches have been generated.

These findings are not an exhaustive proof of exploitability, and the absence of additional findings should not be interpreted as proof that the application is secure.