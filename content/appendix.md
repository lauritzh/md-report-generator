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