### \#PEN0001: XSS in Test Shop

A *Cross-Site Scripting* vulnerability has been identified.

---

| Asset         | CWE                                                      | Severity (CVSS v3.1 Base Score) | CVSS v3.1 Vektor                                                                             |
|---------------|----------------------------------------------------------|---------------------------------|----------------------------------------------------------------------------------------------|
| Test Shop | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | High (8.1)                      | [CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N](CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N) |

---

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