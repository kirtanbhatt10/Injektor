# Security Policy

## Responsible use

Injektor sends adversarial prompts to LLM endpoints. Only run it against systems you own or are explicitly authorized to assess. The bundled demo server is intentionally vulnerable and must never be exposed beyond loopback.

## Reporting a vulnerability in Injektor

If you find a security issue in Injektor itself (for example, a way for a report to leak credentials, or for the demo to bind to a non-loopback address), please **do not open a public issue**.

Instead, use GitHub's [private vulnerability reporting](https://github.com/kirtanbhatt10/Injektor/security/advisories/new) for this repository. Include:

- a description of the issue and its impact
- steps to reproduce
- the affected version (`pip show injektor`)

You can expect an acknowledgement as soon as possible, and a fix or mitigation plan once the issue is confirmed.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
