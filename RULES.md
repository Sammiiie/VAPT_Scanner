# Rule catalogue

Generated with `vapt rules --format md`.

| Rule | Severity | Title | CWE | OWASP |
|---|---|---|---|---|
| VAPT-AUTH-001 | High | Hard-coded credential comparison | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-AUTH-002 | Medium | Weak password policy | CWE-521 | A07:2021 Identification and Authentication Failures |
| VAPT-AUTH-003 | Low | Authorization check missing on mutating endpoint (heuristic) | CWE-862 | A01:2021 Broken Access Control |
| VAPT-CFG-001 | Medium | Custom errors turned off | CWE-209 | A05:2021 Security Misconfiguration |
| VAPT-CFG-002 | Medium | Debug compilation enabled | CWE-489 | A05:2021 Security Misconfiguration |
| VAPT-CFG-003 | Medium | Cookies not restricted to HTTPS / HttpOnly | CWE-614 | A05:2021 Security Misconfiguration |
| VAPT-CFG-004 | Medium | ASP.NET tracing enabled | CWE-489 | A05:2021 Security Misconfiguration |
| VAPT-CFG-005 | High | Request validation or ViewState MAC disabled | CWE-642 | A05:2021 Security Misconfiguration |
| VAPT-CFG-006 | Medium | Directory browsing enabled | CWE-548 | A05:2021 Security Misconfiguration |
| VAPT-CFG-007 | Low | Server version header not removed | CWE-200 | A05:2021 Security Misconfiguration |
| VAPT-CFG-010 | Medium | Detailed errors enabled in non-development settings | CWE-209 | A05:2021 Security Misconfiguration |
| VAPT-CFG-011 | Low | AllowedHosts accepts any host | CWE-644 | A05:2021 Security Misconfiguration |
| VAPT-CFG-012 | Low | Verbose logging in production settings | CWE-532 | A09:2021 Security Logging and Monitoring Failures |
| VAPT-CFG-013 | High | Token validation disabled in configuration | CWE-347 | A07:2021 Identification and Authentication Failures |
| VAPT-CFG-014 | Low | Cleartext HTTP endpoint in configuration | CWE-319 | A02:2021 Cryptographic Failures |
| VAPT-CFG-015 | Medium | Sensitive data logging enabled in configuration | CWE-532 | A09:2021 Security Logging and Monitoring Failures |
| VAPT-CFG-020 | Medium | Container runs as root | CWE-250 | A05:2021 Security Misconfiguration |
| VAPT-CFG-021 | Low | Unpinned base image | CWE-1357 | A06:2021 Vulnerable and Outdated Components |
| VAPT-CFG-022 | Medium | Development environment baked into deployment | CWE-489 | A05:2021 Security Misconfiguration |
| VAPT-CFG-023 | Low | Remote file added without verification | CWE-494 | A08:2021 Software and Data Integrity Failures |
| VAPT-CFG-024 | High | Secret passed via ENV/ARG | CWE-798 | A05:2021 Security Misconfiguration |
| VAPT-CFG-025 | High | Privileged container | CWE-250 | A05:2021 Security Misconfiguration |
| VAPT-CFG-030 | High | Target framework out of support | CWE-1104 | A06:2021 Vulnerable and Outdated Components |
| VAPT-CFG-031 | Low | Built-in security analyzers suppressed | CWE-1164 | A05:2021 Security Misconfiguration |
| VAPT-CMD-001 | High | OS command built from runtime values | CWE-78 | A03:2021 Injection |
| VAPT-CODE-001 | High | Dynamic code evaluation | CWE-94 | A03:2021 Injection |
| VAPT-CRYPTO-001 | Medium | Weak hash algorithm (MD5 / SHA-1) | CWE-328 | A02:2021 Cryptographic Failures |
| VAPT-CRYPTO-002 | High | Broken cipher (DES / 3DES / RC2) | CWE-327 | A02:2021 Cryptographic Failures |
| VAPT-CRYPTO-003 | High | ECB cipher mode | CWE-327 | A02:2021 Cryptographic Failures |
| VAPT-CRYPTO-004 | High | Hard-coded encryption key or IV | CWE-321 | A02:2021 Cryptographic Failures |
| VAPT-CRYPTO-005 | Medium | Non-cryptographic random used for security value | CWE-338 | A02:2021 Cryptographic Failures |
| VAPT-CRYPTO-006 | Medium | Weak PBKDF2 configuration | CWE-916 | A02:2021 Cryptographic Failures |
| VAPT-DAST-001 | High | Site served over plain HTTP | CWE-319 | A02:2021 Cryptographic Failures |
| VAPT-DAST-002 | Medium | Missing or weak HSTS header | CWE-523 | A05:2021 Security Misconfiguration |
| VAPT-DAST-003 | Medium | Missing or weak Content-Security-Policy | CWE-1021 | A05:2021 Security Misconfiguration |
| VAPT-DAST-004 | Medium | Clickjacking protection missing | CWE-1021 | A05:2021 Security Misconfiguration |
| VAPT-DAST-005 | Low | X-Content-Type-Options missing | CWE-693 | A05:2021 Security Misconfiguration |
| VAPT-DAST-006 | Low | Referrer-Policy missing | CWE-200 | A05:2021 Security Misconfiguration |
| VAPT-DAST-007 | Low | Technology/version disclosure in headers | CWE-200 | A05:2021 Security Misconfiguration |
| VAPT-DAST-008 | Medium | Cookie missing security attributes | CWE-614 | A05:2021 Security Misconfiguration |
| VAPT-DAST-009 | High | CORS policy trusts arbitrary origins | CWE-942 | A05:2021 Security Misconfiguration |
| VAPT-DAST-010 | Low | HTTP TRACE enabled | CWE-693 | A05:2021 Security Misconfiguration |
| VAPT-DAST-011 | High | Sensitive file or endpoint publicly reachable | CWE-538 | A05:2021 Security Misconfiguration |
| VAPT-DAST-012 | Medium | Detailed error / stack trace returned | CWE-209 | A05:2021 Security Misconfiguration |
| VAPT-DAST-013 | Medium | Input reflected without HTML encoding | CWE-79 | A03:2021 Injection |
| VAPT-DAST-014 | High | TLS certificate problem | CWE-295 | A02:2021 Cryptographic Failures |
| VAPT-DAST-015 | Medium | Legacy TLS protocol accepted | CWE-326 | A02:2021 Cryptographic Failures |
| VAPT-DAST-016 | Medium | Directory listing enabled | CWE-548 | A05:2021 Security Misconfiguration |
| VAPT-DAST-017 | Low | API documentation exposed | CWE-200 | A05:2021 Security Misconfiguration |
| VAPT-DEP-000 | Info | Online dependency audit could not run |  | A06:2021 Vulnerable and Outdated Components |
| VAPT-DEP-001 | High | Vulnerable NuGet package | CWE-1395 | A06:2021 Vulnerable and Outdated Components |
| VAPT-DESER-001 | Critical | Insecure formatter (BinaryFormatter and friends) | CWE-502 | A08:2021 Software and Data Integrity Failures |
| VAPT-DESER-002 | High | Json.NET TypeNameHandling enabled | CWE-502 | A08:2021 Software and Data Integrity Failures |
| VAPT-DESER-003 | High | JavaScriptSerializer with type resolver | CWE-502 | A08:2021 Software and Data Integrity Failures |
| VAPT-DESER-004 | Medium | Serializer type chosen from runtime string | CWE-502 | A08:2021 Software and Data Integrity Failures |
| VAPT-JS-001 | Medium | JavaScript eval / Function constructor | CWE-95 | A03:2021 Injection |
| VAPT-JS-002 | Low | Auth token stored in Web Storage | CWE-922 | A07:2021 Identification and Authentication Failures |
| VAPT-LDAP-001 | High | LDAP filter built from runtime values | CWE-90 | A03:2021 Injection |
| VAPT-PATH-001 | High | Uploaded file name used to build a file path | CWE-22 | A01:2021 Broken Access Control |
| VAPT-PATH-002 | High | Request data used directly in a file system path | CWE-22 | A01:2021 Broken Access Control |
| VAPT-PATH-003 | Medium | Archive entry path used without validation (Zip Slip) | CWE-22 | A01:2021 Broken Access Control |
| VAPT-REGEX-001 | Medium | Regular expression built from runtime input without a timeout | CWE-1333 | A04:2021 Insecure Design |
| VAPT-SECRET-001 | Critical | Private key | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-002 | High | AWS access key ID | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-003 | Critical | AWS secret access key | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-004 | Critical | GitHub token | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-005 | Critical | GitLab token | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-006 | High | Slack token or webhook | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-007 | Critical | Stripe live key | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-008 | High | Google API key | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-009 | Critical | Azure storage / Service Bus key | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-010 | High | Azure SAS token | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-011 | Critical | SendGrid API key | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-012 | High | AI provider API key | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-013 | High | Package registry token | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-014 | Medium | JSON Web Token | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-015 | High | Database connection string with password | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-016 | High | Credentials embedded in URI | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-017 | Medium | Hard-coded password or secret | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-020 | High | Private key / certificate file committed | CWE-798 | A07:2021 Identification and Authentication Failures |
| VAPT-SECRET-021 | Low | .env file committed | CWE-538 | A05:2021 Security Misconfiguration |
| VAPT-SQL-001 | Critical | SQL query built from runtime values passed to a database API | CWE-89 | A03:2021 Injection |
| VAPT-SQL-002 | Critical | SQL CommandText assigned from a runtime-built string | CWE-89 | A03:2021 Injection |
| VAPT-SQL-003 | Critical | Dapper / micro-ORM query built from runtime values | CWE-89 | A03:2021 Injection |
| VAPT-SQL-004 | High | SQL statement assembled with string interpolation | CWE-89 | A03:2021 Injection |
| VAPT-SQL-005 | High | SQL statement assembled with string concatenation or string.Format | CWE-89 | A03:2021 Injection |
| VAPT-SSRF-001 | High | Outbound request to a URL taken from the request | CWE-918 | A10:2021 Server-Side Request Forgery |
| VAPT-TLS-001 | High | TLS certificate validation disabled | CWE-295 | A07:2021 Identification and Authentication Failures |
| VAPT-TLS-002 | High | Obsolete SSL/TLS protocol enabled | CWE-326 | A02:2021 Cryptographic Failures |
| VAPT-TLS-003 | Low | Cleartext HTTP endpoint in code | CWE-319 | A02:2021 Cryptographic Failures |
| VAPT-WEB-001 | Medium | CORS allows any origin | CWE-942 | A05:2021 Security Misconfiguration |
| VAPT-WEB-002 | High | CORS reflects every origin | CWE-942 | A05:2021 Security Misconfiguration |
| VAPT-WEB-003 | Medium | Developer exception page not limited to Development | CWE-209 | A05:2021 Security Misconfiguration |
| VAPT-WEB-004 | Medium | EF Core sensitive data logging enabled | CWE-532 | A09:2021 Security Logging and Monitoring Failures |
| VAPT-WEB-005 | Medium | Anti-forgery validation disabled | CWE-352 | A01:2021 Broken Access Control |
| VAPT-WEB-006 | Medium | Insecure cookie flags | CWE-614 | A05:2021 Security Misconfiguration |
| VAPT-WEB-007 | Critical | JWT signature or lifetime validation disabled | CWE-347 | A07:2021 Identification and Authentication Failures |
| VAPT-WEB-008 | Medium | JWT issuer / audience validation disabled | CWE-287 | A07:2021 Identification and Authentication Failures |
| VAPT-WEB-009 | Medium | HTTPS metadata requirement disabled | CWE-319 | A07:2021 Identification and Authentication Failures |
| VAPT-WEB-010 | Medium | Possible open redirect | CWE-601 | A01:2021 Broken Access Control |
| VAPT-WEB-011 | Medium | Exception details returned to the client | CWE-209 | A05:2021 Security Misconfiguration |
| VAPT-WEB-012 | Medium | Request validation disabled | CWE-20 | A03:2021 Injection |
| VAPT-WEB-013 | Medium | Sensitive data written to logs | CWE-532 | A09:2021 Security Logging and Monitoring Failures |
| VAPT-WEB-020 | Low | HTTPS redirection not configured | CWE-319 | A05:2021 Security Misconfiguration |
| VAPT-WEB-021 | Low | HSTS not enabled | CWE-523 | A05:2021 Security Misconfiguration |
| VAPT-WEB-022 | Info | No rate limiting configured | CWE-770 | A04:2021 Insecure Design |
| VAPT-XPATH-001 | High | XPath expression built from runtime values | CWE-643 | A03:2021 Injection |
| VAPT-XSS-001 | Medium | Html.Raw renders unencoded HTML | CWE-79 | A03:2021 Injection |
| VAPT-XSS-002 | Medium | Unencoded HTML/markup string created from runtime value | CWE-79 | A03:2021 Injection |
| VAPT-XSS-003 | High | Request data written directly to the response | CWE-79 | A03:2021 Injection |
| VAPT-XSS-004 | Medium | DOM sink assigned dynamic HTML | CWE-79 | A03:2021 Injection |
| VAPT-XXE-001 | High | XML parser allows DTDs / external entities | CWE-611 | A05:2021 Security Misconfiguration |
