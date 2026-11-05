# Pre-Patch Security Validation

**Date:** 2026-11-05  
**Commit:** `e3f681284944d026f26774b797be04ca517cbf98`  
**CI run:** https://github.com/fabinho5/cybersecurity_lab_devsecops/actions/runs/42025903859

## F01 — Unauthorized Grade Modification

Three negative security tests failed. The API returned HTTP 200 instead of the required HTTP 401 for anonymous requests or HTTP 403 for unauthorized authenticated requests.

The tested scenarios involved an anonymous grade update, a student modifying their own grade, and a professor modifying a grade outside their assigned course.

The legitimate professor and administrator update tests passed.

**Validation status:** Confirmed — missing authorization enforcement demonstrated through executable tests. Verification of unchanged data after denied requests remains pending because the response-status assertions failed first.

## F05 — Path Traversal and File Access

Three negative security tests failed. The API returned HTTP 200 for an unauthenticated material download, a parent-directory traversal request, and an absolute-path escape request.

The legitimate authenticated material download test passed.

**Validation status:** Confirmed — unauthorized file-access responses and insufficient path restrictions demonstrated through executable tests. The response-content assertions remain to be verified after repair.

## CI Security Gate

The security regression job failed with 6 failed and 3 passed tests. The functional test and static analysis jobs succeeded. The Docker build job was skipped because the security regression dependency did not pass.

**Conclusion:** The pre-patch CI demonstrates security requirement violations and confirms that the security regression gate prevents image publication when the selected tests fail.