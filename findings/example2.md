<!--
title: XXE in Test Shop
asset: Test Shop
CWE-ID: CWE-611
CWE-Link: https://cwe.mitre.org/data/definitions/611.html
comment: The API processes external entities that are included within the request body.
cvss:
    AV: N # Attack Vector: Network (N), Adjacent (A), Local (L), Physical (P)
    AC: L # Attack Complexity: Low (L), High (H)
    AT: N # Attack Requirements: None (N), Present (P)
    PR: N # Privileges Required: None (N), Low (L), High (H)
    UI: N # User Interaction: None (N), Passive (P), Active (A)
    VC: H # Vulnerable System Confidentiality: High (H), Low (L), None (N)
    VI: H # Vulnerable System Integrity: High (H), Low (L), None (N)
    VA: N # Vulnerable System Availability: High (H), Low (L), None (N)
    SC: N # Subsequent System Confidentiality: High (H), Low (L), None (N)
    SI: N # Subsequent System Integrity: High (H), Low (L), None (N)
    SA: N # Subsequent System Availability: High (H), Low (L), None (N)
-->
#### Description
This type of vulnerability arises, if an application processes XML and is configured to support external entities.

Exemplary Payload:    
``` { .XML hl_lines="2 4"}
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE abcd [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<example>
    <item>&xxe;</item>
</example>
```

#### Recommendation
It is recommended to completely disable external entities (DTDs). Further guidance can be found in OWASP's [*XML External Entity Prevention Cheat Sheet*](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

#### References
* [OWASP: XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
