# Contributing to Naway

Thank you for contributing to Naway. Contributions may include bug reports,
design discussions, documentation, and code changes.

## Before You Start

- Search existing issues and pull requests before opening a new one.
- Use GitHub Issues for reproducible bugs and scoped feature proposals.
- Use the private process in `SECURITY.md` for vulnerabilities.
- Discuss large protocol, compatibility, or architecture changes before implementation.

## Development Environment

Naway requires a stable Rust toolchain. Java SDK work additionally requires
JDK 11 or later and Maven. Redis, Nacos, Kafka, and other external services are
only needed by their corresponding live tests. The Chinese `source.md` file
documents local environment variables without embedding credentials.

Typical validation commands are:

```bash
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
```

## Pull Requests

- Keep each pull request focused on one coherent change.
- Explain the problem, behavior change, compatibility impact, and resource bounds.
- Update `CHANGELOG.md` and the relevant Chinese product or architecture documents.
- Keep secrets, tokens, internal hostnames, and production data out of commits.
- Ensure generated files and SDK contracts remain synchronized when protobuf changes.

Project architecture and product documentation are maintained in Chinese.
Open-source governance, legal, security, and contribution documents are
maintained in English.

## Review and Acceptance

Maintainers review correctness, compatibility, security, bounded-resource
behavior, operational impact, and documentation. A maintainer may request that
a large change be split into smaller pull requests. Acceptance is not guaranteed
and may depend on the project roadmap described in `GOVERNANCE.md`.

## Licensing

Unless explicitly stated otherwise, contributions are licensed under either
Apache-2.0 or MIT, at the recipient's option. By submitting a contribution, you
confirm that you have the right to provide it under those terms.
