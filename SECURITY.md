# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier versions | No |

Until Naway reaches a stable release, security fixes are applied to the latest
development line only.

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting or create a private security advisory at:

https://github.com/nasa-runtime/naway/security/advisories/new

Include the affected version or commit, deployment assumptions, reproduction
steps, impact, and any suggested mitigation. Remove production credentials,
tokens, personal data, and unrelated confidential information.

Maintainers aim to acknowledge a report within five business days and provide an
initial assessment within ten business days. Resolution time depends on severity,
complexity, and coordinated disclosure requirements. These targets are best-effort
and are not a service-level agreement.

Please allow maintainers a reasonable remediation window before public disclosure.
Credit will be offered when desired and appropriate.

## Scope

Reports concerning authentication, authorization, request smuggling, resource
exhaustion, unsafe parsing, secrets exposure, control-plane integrity, gRPC edge
fan-out, Redis transport, and official SDKs are in scope. Security defects in an
upstream dependency should also be reported upstream when appropriate.
