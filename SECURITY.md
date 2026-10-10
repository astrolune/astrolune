<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Security Policy

## Security status

This policy covers the development branch, which is where all current work lands. AstroLune has no published release and no completed external audit, so the properties it offers are those its documents state and its tests exercise; [the implementation status](docs/08-implementation-status.md) records every area and its bounds, and the scope section below lists the documented mechanisms that carry no deployed protection.

## Supported versions

| Version | Security support |
|---|---|
| Unreleased development branch | Best-effort triage |
| Published releases | None yet; the process is in [`RELEASING.md`](RELEASING.md) |

This table gains a supported line for each release once releases ship.

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
- double-sign prevention, signing-anchor rollback detection, and keystore isolation;
- release manifest signing and artifact verification bypasses;
- non-deterministic contract or parallel execution;
- state commitment, snapshot, recovery, or sync verification bypasses;
- canonical decoder confusion, memory exhaustion, and P2P denial of service;
- DNS ownership and proof failures.

## Out of scope for security guarantees

Declared-but-unimplemented backends, documented future mechanisms, benchmark targets, and privacy or anonymity designs are not claims of deployed protection. Findings that improve these designs are welcome; there is no bounty or reward program.

Several mechanisms are implemented and locally tested but deliberately bounded, and their limits are not defects. Bounded parallel signature verification splits independent verifications and is not the cofactored batch equation; [scope](docs/09-cryptographic-foundations.md#bounded-parallel-verification). The signing anchor detects a restored older journal through an independently provisioned store and does not provide hardware isolation or survive a coordinated rewrite of both stores; [threat boundary](docs/53-key-custody-and-release-authority.md). The consensus model is bounded exhaustive exploration at one height, never a proof; [bounds](docs/55-formal-consensus-model.md). Adversarial simulations hold Byzantine coalitions below the accountability threshold; [scope](docs/46-rotating-network-simulations.md). Release signing ships the mechanism only: this repository invents no signing identity or key. Advisory scanning is a database check over the Rust workspace, not an implementation audit, and its licence/ban coverage gap is recorded; [review](docs/51-dependency-and-security-review.md). No external cryptography, consensus, runtime or security audit has been performed.

Testing must be authorized, targeted, non-destructive, and must not disrupt third-party systems or access data without permission.
