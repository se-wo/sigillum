# Security Policy

## Supported versions

Sigillum is pre-1.0. Security fixes land on `main` and ship in the next
release; only the latest release is supported.

## Reporting a vulnerability

Please do **not** open a public issue. Report privately through GitHub's
[private vulnerability reporting](https://github.com/se-wo/sigillum/security/advisories/new)
with a description, affected version(s) and, if possible, a reproducer.

You can expect an acknowledgement within a few days and a coordinated fix
and advisory once the issue is confirmed.

## Verifying releases

Release images and charts are signed with cosign and carry SLSA build
provenance attestations. See the README's
[Supply chain](README.md#supply-chain) section for the verify commands.
