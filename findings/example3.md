<!--
title: Open Redirect in Test Shop
asset: Test Shop
CWE-ID: CWE-601
CWE-Link: https://cwe.mitre.org/data/definitions/601.html
comment: The to parameter is used to redirect the end-user without sufficient validation.
finding_id: PEN20250003
cvss:
    AV: N # Attack Vector: Network (N), Adjacent (A), Local (L), Physical (P)
    AC: H # Attack Complexity: Low (L), High (H)
    AT: P # Attack Requirements: None (N), Present (P)
    PR: H # Privileges Required: None (N), Low (L), High (H)
    UI: A # User Interaction: None (N), Passive (P), Active (A)
    VC: H # Vulnerable System Confidentiality: High (H), Low (L), None (N)
    VI: N # Vulnerable System Integrity: High (H), Low (L), None (N)
    VA: N # Vulnerable System Availability: High (H), Low (L), None (N)
    SC: N # Subsequent System Confidentiality: High (H), Low (L), None (N)
    SI: N # Subsequent System Integrity: High (H), Low (L), None (N)
    SA: N # Subsequent System Availability: High (H), Low (L), None (N)
-->
#### Description
This type if vulnerability arises, if an application redirects to untrusted URLs.

Exemplary Request:
```http
GET /redirect?to=https://lhq.at HTTP/1.1
Host: test.shop
```

Response:
``` { .HTTP hl_lines="2 "}
HTTP/1.1 302 Found
Location: https://lhq.at
```

#### Recommendation
It is recommended to do not dynamically redirect to untrusted URLs. Further guidance can be found in OWASP's [*Open Redirect Prevention Cheat Sheet*](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).

#### References
* [OWASP: Open Redirect Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
