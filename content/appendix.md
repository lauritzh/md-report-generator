## Appendix
This chapter includes further supporting materials for this pentest report. 

#### Used Tools
The following tools were used in the course of this pentest:

* [Caido: A lightweight web security auditing toolkit](https://caido.io/)
* [Burp Suite Professional: Intercepting Proxy](https://portswigger.net/burp/pro)
* [nmap: Network Mapper](https://nmap.org/)
* [Nikto: Web server scanner](https://cirt.net/Nikto2)
* [SQLmap: SQL injection and database tool](https://sqlmap.org/)
* [Nuclei: Vulnerability scanner](https://github.com/projectdiscovery/nuclei)
* [AuRA: Auth. Request Analyser](https://chrome.google.com/webstore/detail/aura-auth-request-analyser/clonpaankbndgnciijbiokgjeofjdpeg)
* [sslscan: SSL/TLS service scanner](https://github.com/rbsec/sslscan)
* [testssl: SSL/TLS service scanner](https://github.com/drwetter/testssl.sh)
* [metasploit: penetration testing framework](https://www.metasploit.com/)
* [Chromium: Web Browser + Development Tools](https://www.chromium.org/)


#### Methodology
This penetration test was performed based on industry standards such as the *OWASP Web Security Testing Guide* and the *OWASP Top 10*. The *OWASP Top 10* is regularly updated and covers the most common and relevant threats for web applications. Pentests of mobile applications are additionally performed based on the *OWASP Mobile Security Testing Guide*. 
Further, pentests of single sign-on (*SSO*) solutions are performed based on best practices such as the *OAuth 2.0 Security Best Current Practice* as well as current research.

##### Severity Classification

All identified findings are classified according to the Common Vulnerability Scoring System (*CVSS v4.0*). CVSS provides a standardized method to evaluate the technical impact and exploitability of a vulnerability. Scores range from **0.0 to 10.0** and map to the following severity categories:

| Severity Level | CVSS Score Range | Description |
|----------------|------------------|-------------|
| **None**       | 0.0              | No direct security impact. However, the condition may still support an attack chain when combined with other weaknesses. |
| **Low**        | 0.1 – 3.9        | Limited impact on systems or users. Exploitation typically requires specific circumstances or offers minimal gain to an attacker. |
| **Medium**     | 4.0 – 6.9        | Noticeable impact on confidentiality, integrity, or availability. Attackers may exploit the issue with moderate effort or preconditions. |
| **High**       | 7.0 – 8.9        | Serious security implications. Exploitation is feasible and may significantly affect data or system operations. |
| **Critical**   | 9.0 – 10.0       | Severe risk requiring immediate attention. Vulnerabilities in this range are typically easy to exploit or result in major compromise of systems or data. |

Using CVSS ensures consistent prioritization of remediation efforts. Each finding in this report includes its CVSS score, an explanation of the underlying issue, the potential impact, and actionable remediation recommendations.


##### Timeline of a pentest 
A typical timeline of a pentest execution could look as follows:

1. Organizational meeting to discuss the general conditions and the scope
2. Technical meeting to discuss which preparatory actions need to be taken
3. Execution of the pentest
    1. Continuous communications and status updates for all stakeholders, for instance via chat or e-mail
    2. Optional: Immediate access to results in a draft state, for instance via a shared folder or Git repository
4. Creation and submission of the detailed PDF report
5. Final meeting with a presentation of results

After the pentest results are shared, the remediation phase takes place. Optionally, during this phase further consulting can take place. After the identified issues are remediated, typically a retest is performed to verify that the applied measurements effectively address the identified vulnerabilities. 
