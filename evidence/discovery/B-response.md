# Static Security Review — Academic Services REST API

Scope: `baseline_secure_coding_api.py`, lines 1–159.

Method: Static source inspection only. No code execution, external tools, browsing, or published solutions were used.

Overall assessment: The source contains several high-confidence security weaknesses, principally in authorization enforcement, filesystem access, authentication configuration, and grade modification. Some risks are conditional on deployment or security policies not specified in the application context.

Severity ratings below are estimates based on the described multi-user academic environment, not a confirmed production threat model.

## 1. Findings summary

| ID   | Finding                                                    | Affected location                                 | Severity | Confidence |
| ---- | ---------------------------------------------------------- | ------------------------------------------------- | -------- | ---------- |
| F-01 | Unrestricted grade modification                            | `update_grade()` L128–142                         | Critical | High       |
| F-02 | Unauthorized student profile and grade disclosure          | `get_profile()` L115–120; `get_grades()` L122–126 | High     | High       |
| F-03 | Path traversal and arbitrary readable-file disclosure      | `download_file()` L144–148                        | High     | High       |
| F-04 | Hardcoded Flask session signing secret                     | Application configuration L7–8                    | High     | High       |
| F-05 | Hardcoded plaintext account credentials                    | `User`, `USERS`, `login()` L27–42, L82–94         | High\*   | High       |
| F-06 | Debug server bound to all network interfaces               | Application entry point L158–159                  | High\*   | High       |
| F-07 | Missing grade input and consistency validation             | `update_grade()` L130–140                         | Medium   | High       |
| F-08 | Internal exception disclosure and incorrect error handling | `handle_error()` L150–155                         | Medium   | High       |
| F-09 | No application-level login throttling                      | `login()` L82–89                                  | Medium\* | Medium     |
| F-10 | Potential logout CSRF                                      | `logout()` L98–101                                | Low\*    | Medium     |

\*Severity depends on deployment conditions, access to the source or credentials, or browser behavior. These conditions are not established by the supplied material.

## 2. Supporting explanations

### F-01 — Unrestricted grade modification

Location: `update_grade()`, lines 128–142.

Demonstrated code facts: The endpoint accepts JSON containing `student_id`, `course_id`, and `grade`. It calls `find_grade()` and either modifies an existing record or inserts a new record into `GRADES`. No authentication, role check, or course-assignment check occurs.

Input and flow: Attacker-controlled JSON → `request.get_json()` → `find_grade()` → direct mutation of `GRADES`.

Root cause: Missing server-side authorization on a sensitive write operation.

Preconditions and impact: Any client able to reach the endpoint can attempt to modify or create grades. The supplied roles and professor-course assignments strongly suggest that changes should be restricted, but the precise authorization policy is unspecified.

Proposed test: In an isolated test instance, submit a grade update without logging in, then retrieve the affected grade to determine whether it changed. Repeat with a student session and a professor assigned to a different course.

Uncertainty: Exact permitted grade editors are unknown. The absence of authorization checks is directly established.

Confidence: High.&#x20;

baseline_secure_coding_api.py



### F-02 — Unauthorized student profile and grade disclosure

Location: `get_profile()`, lines 115–120; `get_grades()`, lines 122–126.

Demonstrated code facts: Both endpoints accept a student identifier directly from the URL and retrieve records without consulting `flask.session`.

Input and flow: Attacker-controlled URL student ID → integer conversion → `STUDENT_PROFILES` or `GRADES` lookup → JSON response.

Root cause: Missing authentication and object-level authorization, consistent with an insecure direct object reference (IDOR) vulnerability.

Preconditions and impact: Anyone able to reach the API can request profiles and grades by identifier. This can disclose names, email addresses, programs, and academic grades.

Proposed test: Request both endpoints while unauthenticated, then repeat while authenticated as one student but requesting another student's identifier. Compare responses with the intended access policy.

Uncertainty: Whether professors, administrators, or students may access particular records is not defined. Public disclosure of grades and profiles would require explicit policy justification.

Confidence: High.&#x20;

baseline_secure_coding_api.py



### F-03 — Path traversal and arbitrary file disclosure

Location: `download_file()`, lines 144–148.

Demonstrated code facts: The `path` query parameter is joined directly with `MATERIALS_DIR`, and the resulting path is passed to `flask.send_file()`.

Input and flow: Attacker-controlled `path` → `MATERIALS_DIR / raw_path` → filesystem read by `send_file()` → response.

Root cause: No verification that the resolved path remains within the materials directory. Parent-directory components and absolute paths are not rejected.

Preconditions and impact: A client can attempt to retrieve any file readable by the application process, subject to filesystem permissions and path knowledge. Potential targets include application source and configuration files.

Proposed test: In an isolated environment, create a harmless marker file outside `materials` and request it through a parent-directory path. Confirm whether its contents are returned.

Uncertainty: Actual readable files and deployment permissions are unknown. Whether teaching materials themselves require authentication is also unspecified.

Confidence: High.&#x20;

baseline_secure_coding_api.py



### F-04 — Hardcoded Flask session signing secret

Location: Application configuration, line 8; session assignments, lines 91–94.

Demonstrated code facts: `SECRET_KEY` is assigned a fixed, source-visible string. Login stores user identity, role, student identifier, and course assignments in the Flask session.

Input and flow: With knowledge of the signing secret, an attacker can potentially construct a valid signed Flask session cookie containing attacker-selected identity or role values.

Root cause: A predictable, shared session-signing secret undermines session integrity.

Preconditions and impact: An attacker must know or recover the secret and be able to supply a session cookie. Forged identity claims could be reflected by `/me`. Privilege escalation through protected endpoints is not demonstrated because the supplied endpoints do not enforce session-based authorization.

Proposed test: In a controlled instance, construct a session cookie using the configured secret with a modified role claim, and determine whether `/me` accepts that claim.

Uncertainty: No downstream session consumers are provided.

Confidence: High for the session-integrity issue; conditional for broader privilege escalation.&#x20;

baseline_secure_coding_api.py

baseline_secure_coding_api.py



### F-05 — Hardcoded plaintext account credentials

Location: `User` and `USERS`, lines 27–42; `login()`, lines 82–89.

Demonstrated code facts: Account passwords are stored as plaintext string values in the source. Login compares a supplied password directly with the stored value.

Input and flow: Attacker-controlled username and password → `USERS.get()` → direct password comparison → session creation.

Root cause: Credentials are embedded in application source without password hashing or a separate protected credential store.

Preconditions and impact: Anyone who learns the source-defined credentials can authenticate as the corresponding account, including the administrator account. The file-disclosure weakness may provide a route to recovering those credentials.

Proposed test: On a disposable instance, authenticate using one seeded account and verify the resulting session identity. Separately inspect whether credential values are stored only as plaintext.

Uncertainty: The credentials may be intended solely for the teaching demonstration. The finding becomes especially significant if the application is deployed with them unchanged.

Confidence: High.&#x20;

baseline_secure_coding_api.py



### F-06 — Debug server exposed on all interfaces

Location: Application entry point, lines 158–159.

Demonstrated code facts: The application launches with `debug=True` and `host="0.0.0.0"` when executed directly.

Input and flow: Network-supplied HTTP requests → Flask development server → debugging and error-handling functionality.

Root cause: Debug mode is enabled in a configuration that listens on all network interfaces.

Preconditions and impact: If the application is launched directly and the server is reachable by untrusted clients, development debugging functionality may be exposed. Depending on its protections and configuration, this can increase information-disclosure and potentially code-execution risk.

Proposed test: In an isolated environment, start the application using its configured entry point and inspect whether debugging functionality is externally reachable. Do not assume unrestricted debugger execution.

Uncertainty: The supplied source does not establish actual deployment configuration, network exposure, or debugger accessibility. The global exception handler may also affect which errors reach the debugger.

Confidence: High for unsafe debug configuration; conditional for exploitability.&#x20;

baseline_secure_coding_api.py



### F-07 — Missing grade input and consistency validation

Location: `update_grade()`, lines 130–140.

Demonstrated code facts: Incoming JSON field values are used without validation of types, ranges, student existence, or course existence.

Input and flow: Arbitrary JSON values → lookup or insertion → stored grade records.

Root cause: Missing input schema validation and record-consistency checks.

Preconditions and impact: A client can insert structurally invalid records or unexpected grade values. For example, a string student identifier may fail to match an existing integer identifier and result in a separate record.

Proposed test: On disposable records, submit string identifiers, nonexistent identifiers, nonnumeric grades, and missing fields. Check whether invalid records are accepted or server errors occur.

Uncertainty: The permitted numeric grade range and academic grading policy are not supplied; an out-of-range grade should be treated as a policy assumption rather than a proven violation.

Confidence: High for missing validation.&#x20;

baseline_secure_coding_api.py



### F-08 — Internal exception disclosure and incorrect error handling

Location: `handle_error()`, lines 150–155.

Demonstrated code facts: The global exception handler returns the exception's string representation and Python class name in a JSON response, always using HTTP 500.

Input and flow: Attacker-controlled malformed input or invalid routes → exception → global handler → exception details in the response.

Root cause: Direct exposure of internal error information and failure to distinguish expected HTTP errors from unexpected server failures.

Preconditions and impact: A client can trigger error conditions to obtain diagnostic information. Some exceptions may reveal internal filesystem paths or implementation details. Ordinary HTTP errors may also be incorrectly reported as server failures.

Proposed test: Request a nonexistent route, supply a nonnumeric student identifier, and reference a nonexistent file. Inspect status codes and exposed error details.

Uncertainty: The sensitivity of disclosed details depends on the particular exception. Full stack-trace disclosure is not demonstrated by this handler.

Confidence: High.&#x20;

baseline_secure_coding_api.py



### F-09 — No application-level login throttling

Location: `login()`, lines 82–89.

Demonstrated code facts: The endpoint checks credentials and immediately responds with 401 on failure. No attempt counter, lockout, delay, or application-level rate limit is present.

Input and flow: Repeated attacker-controlled credential submissions → password comparisons → authentication responses.

Root cause: Missing application-level resistance to repeated authentication attempts.

Preconditions and impact: An attacker able to send repeated requests may attempt credential guessing, especially against weak demonstration passwords.

Proposed test: In a controlled instance, submit a bounded sequence of incorrect passwords for a test account and observe whether attempts are restricted.

Uncertainty: A reverse proxy or other external control could implement rate limiting, but none is included in the supplied source.

Confidence: Medium as an exploitable finding; high that application-level throttling is absent.&#x20;

baseline_secure_coding_api.py



### F-10 — Potential logout CSRF

Location: `logout()`, lines 98–101.

Demonstrated code facts: A POST to `/logout` clears the current session without checking a CSRF token or request origin.

Input and flow: Attacker-induced browser POST → logout endpoint → session clearing, if the victim's session cookie accompanies the request.

Root cause: No explicit cross-site request forgery protection on a state-changing endpoint.

Preconditions and impact: A logged-in user must be induced to submit a cross-origin or otherwise untrusted request that includes their session cookie. Successful exploitation would log the victim out.

Proposed test: From a separate test origin, submit a cross-site POST using an authenticated test browser and determine whether the session is cleared.

Uncertainty: Browser cookie behavior and `SameSite` restrictions may prevent the request from carrying the session cookie. Exploitability cannot be established solely from the endpoint code.

Confidence: Medium for the potential weakness; lower for practical exploitation in a modern browser.&#x20;

baseline_secure_coding_api.py



## 3. Security policy assumptions

The following distinctions are important when interpreting the findings.

| Area                  | Demonstrated source behavior                                | Assumed or unknown requirement                                                 |
| --------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Student records       | Any reachable client can request profiles and grades        | Student records are not intended to be public                                  |
| Grade updates         | Any reachable client can create or modify grades            | Changes require an authorized professor or administrator                       |
| Professor assignments | Course assignments exist but are not checked during updates | Professors may update grades only in assigned courses                          |
| Grade validity        | Arbitrary JSON grade values can be stored                   | Grades must meet a defined academic schema and range                           |
| Teaching materials    | File downloads require no authentication                    | Whether materials are public or restricted is unknown                          |
| Session integrity     | A fixed signing secret is present in source                 | Session claims must be trusted for protected operations                        |
| Deployment            | The direct-launch configuration enables debug mode          | Whether that configuration is used outside the teaching environment is unknown |

## 4. Review priorities

I would prioritize validation in this order:

1. F-01 and F-02 — Authorization: Confirm that unauthorized clients can modify grades or retrieve other students' academic records.
2. F-03 — Filesystem containment: Confirm whether the file endpoint can read outside the materials directory.
3. F-04 and F-05 — Authentication integrity: Check whether the seeded credentials and signing secret permit account impersonation.
4. F-06 — Deployment exposure: Establish whether the debug server is reachable beyond the intended environment.
5. F-07 through F-10 — Secondary controls: Assess validation, error handling, authentication throttling, and browser-mediated requests.

There is also a possible authorization-policy issue with unrestricted downloads of teaching materials even after path traversal is addressed. It is not classified as a separate confirmed vulnerability because the supplied context does not state that those materials are restricted.

## 5. Review conclusion

The strongest findings are F-01, F-02, and F-03. Their underlying flaws are directly visible in the supplied source and do not depend on speculative downstream components.

The principal root causes are missing authorization enforcement, unrestricted filesystem-path construction, and unsafe handling of credentials and session-signing material.

All findings remain static-review claims, not runtime-confirmed exploits. The suggested tests are intended to distinguish actual exploitability from code-level concerns and unknown policy assumptions.

No patches were generated, no tests were executed, and no external sources were consulted. This review is limited to the supplied application source; absence of other findings is not proof of security.