# Known Limitations

Date: 2026-02-07

- **Not production hardened**: key management, audit logging, monitoring, and incident response are not implemented.
- **Issuer trust requires configuration**: verifier must be configured with trusted issuer public keys.
- **Revocation privacy tradeoffs**: current model uses credential ID checks; privacy-preserving accumulators are not implemented.
- **Operational security**: no built-in protection against device compromise or malware on clients.
- **Rate limiting**: demo rate limiter is not sufficient for production.
- **Demo/Examples**: examples are for illustration and are not secure deployments.
