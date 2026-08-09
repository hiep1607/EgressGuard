# Security policy

EgressGuard is an experimental security prototype and is not supported for production deployment.

## Reporting

Do not place credentials, tokens, private keys, personal data, real sensitive documents, packet captures, databases, logs, or detailed exploit instructions in a GitHub issue. A private vulnerability-reporting contact will be added before any public release. Until then, coordinate privately with the repository owner without posting sensitive detail.

Do not use real malware to reproduce a defect. Use only the included Simulator and Test Server or a synthetic fixture that contains no user data.

## Known limitations

- The product does not guarantee prevention of all data exfiltration.
- There is no driver, ETW file correlation, payload inspection, TLS interception, code-signing pipeline, or production installer.
- Windows Firewall rules ultimately bind to executable path; hash identity must be refreshed after file replacement.
- The final unsigned Windows Service binary may be blocked by organizational Application Control policy.
- Security, privacy, reboot, long-soak, and multi-DPI acceptance are incomplete.

Security controls must fail safely: do not disable Windows Firewall, Application Control, antivirus, UAC, or system-wide outbound protections to test this project.
