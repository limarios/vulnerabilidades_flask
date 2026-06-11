# Security Policy

## The vulnerabilities in this repository are INTENTIONAL

**Flask Security Lab** is an educational Red Team vs Blue Team laboratory. Every
endpoint under `/vulnerable/*` is **deliberately, knowingly insecure**. The flaws are
the curriculum: each one is paired with a hardened twin under `/secure/*` and a
walkthrough in [`docs/vulnerabilities/`](docs/vulnerabilities/).

> **Do not report the `/vulnerable/*` flaws as security bugs.** SQL injection, XSS,
> command injection, SSTI, IDOR, SSRF, insecure deserialization, JWT signature bypass,
> path traversal, and missing authentication on those routes are *expected* and
> documented. Reports against intentional lab flaws will be closed as "by design."

If you are unsure whether a finding is intentional, check `src/lab/catalog.py` and
`docs/vulnerabilities/` — every shipped vulnerability is listed there.

## Intended scope and use

This project exists to **teach** how common web vulnerabilities work and how to fix
them. It is intended for:

- security training, workshops, and self-study;
- practicing defensive coding by comparing the vulnerable and secure twins;
- exercising the offensive tooling against your **own local instance**.

### Hard rules

- **Loopback only.** Run the lab on `127.0.0.1` / `localhost` and attack only that
  instance. The offensive CLI enforces this at runtime: every command routes through
  `assert_loopback` in `src/red_team/guard.py`, which refuses any target that does not
  resolve to a loopback address before a single request is sent.
- **Never expose this app to the internet** or to any network you do not fully
  control. A public deployment would be a genuinely exploitable, attacker-reachable
  application. Do not host it, do not port-forward to it, do not deploy it.
- **Never run the offensive tooling against systems you do not own** or do not have
  explicit, written authorization to test. The `red_team` package is a teaching aid for
  this lab, not a tool for use against third-party systems.
- Run it on a machine and account you control, ideally inside a container or VM.

## Legal notice — unauthorized access is a crime

Using the techniques or tooling in this repository against systems you do not own or
are not explicitly authorized to test is illegal in most jurisdictions. This is not a
disclaimer of convenience — it reflects real criminal law.

**Brazil**

- **Lei nº 12.737/2012** (the "Lei Carolina Dieckmann"), which introduced Art. 154-A
  into the Código Penal, criminalizes unauthorized access to a computer device to
  obtain, tamper with, or destroy data.
- **Lei nº 14.155/2021** strengthened these provisions, increasing penalties for
  electronic device intrusion and for fraud committed by electronic means.

**International**

- **United States** — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.
- **United Kingdom** — Computer Misuse Act 1990.
- Equivalent unauthorized-access statutes exist across the EU (e.g. the Cybercrime
  Directive 2013/40/EU) and most other jurisdictions.

You are solely responsible for how you use this code. Authorization is the line
between security research and a crime.

## Responsible use of the `red_team` tooling

The `red_team` CLI (`python -m red_team <attack> --target http://127.0.0.1:5000`) is a
deliberately constrained demonstrator:

- **Loopback-guarded** — see `src/red_team/guard.py`; it cannot fire at a non-loopback
  host.
- **Tame by design** — the `load-test` traffic generator is capped at 10 seconds and
  20 workers and responds cleanly to `Ctrl+C`. It demonstrates a mitigation; it is not
  a weapon.
- **Self-contained** — payloads target only the local lab's documented routes and clean
  up after themselves (e.g. the deserialization demo removes the directory it creates).

Use it to learn. Do not adapt it to attack anything but your own local lab.

## Reporting a REAL vulnerability in the project scaffold

If you find a genuine, **unintended** security issue in the project *infrastructure* —
something outside the intentional lab flaws — we want to hear about it. Examples:

- the `assert_loopback` guard can be bypassed to target a non-loopback host;
- the build, container, or dependency chain ships a real supply-chain risk;
- the offensive tooling can cause harm beyond the documented, capped behavior;
- a secret or credential is committed to the repository;
- a `/secure/*` twin does not actually mitigate its vulnerability as documented.

**How to report:**

1. **Do not** open a public issue describing the flaw.
2. Use **GitHub Private Vulnerability Reporting** ("Report a vulnerability" under the
   repository's *Security* tab) if enabled, **or**
3. Contact the maintainer privately at the email listed on the maintainer's GitHub
   profile / repository contact.

Please include reproduction steps, affected files, and the impact. We aim to
acknowledge a valid report promptly and will coordinate a fix and disclosure timeline
with you. Thank you for reporting responsibly.
