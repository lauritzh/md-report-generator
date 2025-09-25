<!--
title: XSS in Test Shop
asset: Test Shop
CWE-ID: CWE-79
CWE-Link: https://cwe.mitre.org/data/definitions/79.html
fixed: true
cvss:
    AV: N # Attack Vector: Network (N), Adjacent (A), Local (L), Physical (P)
    AC: L # Attack Complexity: Low (L), High (H)
    PR: N # Privileges Required: None (N), Low (L), High (H)
    UI: R # User Interaction: None (N), Required (R)
    S: U # Unchanged (U), Changed (C)
    C: H # Confidentiality: High (H), Low (L), None (N)
    I: L # Integrity: High (H), Low (L), None (N)
    A: N # Availability: High (H), Low (L), None (N)
-->
#### Description
A *Cross-Site Scripting* vulnerability has been identified.

This type of vulnerability arises, if an application uses user-controlled inputs to generate dynamic outputs in an insecure manner.


Exemplary Payload:    

```html
<s>test</s>
```

JavaScript:
``` { .javascript linenos="true" linenostart="3" hl_lines="3"}
[...]
function demo() {
    alert(1);
}
```

<img src="images/xss.png" style="width: 75%;">

#### Recommendation
It is recommended to consider all input to the application as potentially dangerous. If user-controlled contents are embedded within the application, they need to be encoded and/or filtered in a *context aware* manner. If the contents are for instance reflected within the JavaScript Context, a different encoding and sanitization needs to be performed than for the HTML context.
Further guidance can be found within OWASP's [*Cross Site Scripting Prevention Cheat Sheet*](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

#### References
* [OWASP: Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)