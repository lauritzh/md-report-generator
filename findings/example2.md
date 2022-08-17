<!--
title: XXE in Test Shop
asset: Test Shop
CWE-ID: CWE-611
CWE-Link: https://cwe.mitre.org/data/definitions/611.html
cvss:
    AV: N # Attack Vector: Network (N), Adjacent (A), Local (L), Physical (P)
    AC: L # Attack Complexity: Low (L), High (H)
    PR: N # Privileges Required: None (N), Low (L), High (H)
    UI: N # User Interaction: None (N), Required (R)
    S: U # Unchanged (U), Changed (C)
    C: H # Confidentiality: High (H), Low (L), None (N)
    I: H # Integrity: High (H), Low (L), None (N)
    A: N # Availability: High (H), Low (L), None (N)
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