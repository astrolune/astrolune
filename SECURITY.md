<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Security Policy

## Experimental status

AstroLune is an unaudited engineering baseline, not production software. No release currently supports economic value or makes security, privacy, anonymity, availability, or finality guarantees.

## Supported versions

| Version | Security support |
|---|---|
| Unreleased development branch | Best-effort triage |
| Published releases | None exist yet |

This table will change only after the project publishes a reviewed release policy.

## Reporting a vulnerability

Do not open a public issue, pull request, discussion, or chat thread containing an undisclosed vulnerability, exploit, private key, credential, personal data, or sensitive infrastructure detail.

Use the repository host's private vulnerability-reporting feature when it is enabled. If no private reporting channel is visible, contact a verified project maintainer through an already published private channel and disclose only enough information to establish contact. This document intentionally does not invent an email address or maintainer identity.

Include:

- affected commit or version;
- affected component and configuration;
- prerequisites and attack surface;
- minimal reproduction or proof of concept;
- expected and observed behavior;
- confidentiality, integrity, availability, or consensus impact;
- suggested mitigation, if known.

Encrypt sensitive material when a verified project key is published. Never send wallet seeds, production credentials, or unrelated user data.

## Response targets

The project aims to acknowledge a complete report within seven days, assess severity and coordinate remediation privately, and credit reporters who request attribution. These are operational targets, not guaranteed service-level agreements. A small or inactive contributor group may take longer.

Public disclosure should be coordinated after affected users have a reasonable opportunity to update. Immediate disclosure may be appropriate when a vulnerability is already actively public, but reporters should still avoid publishing unnecessary exploit details.

## High-priority areas

Reports are especially valuable for:

- consensus safety, liveness, committee selection, rotation, or quorum errors;
- PoTB manipulation and weight/evidence inconsistencies;
- signature, hash, VRF, key derivation, or domain-separation failures;
- double-sign prevention and keystore isolation;
- non-deterministic contract or parallel execution;
- state commitment, snapshot, recovery, or sync verification bypasses;
- canonical decoder confusion, memory exhaustion, and P2P denial of service;
- DNS ownership and proof failures.

## Out of scope for security guarantees

Placeholder binaries, unimplemented traits, documented future mechanisms, benchmark targets, and privacy/anonymity ideas are not claims of deployed protection. Findings that improve these designs are welcome, but no bounty or reward program is promised.

Testing must be authorized, targeted, non-destructive, and must not disrupt third-party systems or access data without permission.
