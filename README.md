# Evidence-First Incident Intake and Triage Lab

[![Automated tests](https://github.com/KingJassem/incident-triage-portfolio/actions/workflows/tests.yml/badge.svg)](https://github.com/KingJassem/incident-triage-portfolio/actions/workflows/tests.yml)

An educational Python portfolio project that processes **synthetic** IT and security event records through validation, duplicate detection, rule-based severity classification, and human-review decisions.

This is not an endpoint scanner, network scanner, SIEM, EDR, or autonomous incident-response system. It demonstrates the intake and triage stage that occurs after an event has been supplied by another system or user.

## What I practiced

- Running and testing a Python command-line application from PowerShell
- Reviewing authentication, phishing, endpoint, and connectivity event records
- Validating required fields, pseudonymous identifiers, and timezone-aware timestamps
- Normalizing event timestamps to UTC for consistent timelines
- Detecting duplicate events and rejecting malformed records
- Assigning transparent, rule-based severity suggestions
- Identifying medium- and high-severity events for human review
- Maintaining an explicit boundary against automated containment
- Verifying expected behavior with automated unit tests and GitHub Actions

## Processing flow

```text
Synthetic JSON events
        |
        v
Strict field and timestamp validation ---> Reject malformed records
        |
        v
Duplicate detection --------------------> Record duplicate event IDs
        |
        v
Transparent classification rules
        |
        v
Severity suggestion + rationale + human-review decision
        |
        v
Advisory output only - no account, network, or endpoint modification
```

## Run it locally

Requirements:

- Python 3.11 or newer
- No external packages, accounts, or cloud services

From PowerShell in the repository folder:

```powershell
python -m unittest discover -s tests -v
python -m triage_portfolio
```

To save the report:

```powershell
python -m triage_portfolio --output output.json
```

## Expected demonstration result

The supplied sample batch contains six synthetic records:

- 4 accepted records
- 1 duplicate event ID
- 1 rejected record with an invalid timestamp
- 3 accepted incidents requiring human review

The scenarios cover failed authentication attempts, a reported suspicious link, a synthetic endpoint-malware alert, and a routine connectivity event.

## Automated verification

The unit-test suite verifies that:

- Failed-login events receive the expected review decision
- Higher-risk authentication and endpoint signals are escalated
- Routine events remain low severity
- Unexpected personal-information fields are rejected
- Incompatible category and signal combinations are rejected
- Duplicate and malformed records are counted correctly
- Timestamps without timezone information are rejected
- Classification remains advisory and never claims to contain a device or account

GitHub Actions runs the same tests automatically on every push and pull request using supported Python versions.

## Project structure

```text
data/sample_events.json       Synthetic demonstration events
tests/test_core.py            Automated unit tests
triage_portfolio/core.py      Validation and classification rules
triage_portfolio/__main__.py  Command-line entry point
triage_portfolio/server.py    Optional localhost-only API demonstration
.github/workflows/tests.yml   Automated GitHub test workflow
```

## Timestamp handling

Input records must include a timezone-aware ISO 8601 timestamp. Accepted timestamps are normalized to UTC and rendered with a trailing `Z`, allowing records from different sources to be placed on one investigation timeline.

Example:

```text
2026-11-11T09:00:00-06:00  ->  2026-11-11T15:00:00Z
```

These values represent the same moment.

## Scope and limitations

- All included events are synthetic.
- The application does not inspect a live endpoint or network.
- It does not connect to an identity provider, helpdesk, SIEM, or EDR.
- It does not enrich IP addresses or perform threat-intelligence lookups.
- Event-ID duplicate detection applies only within one processed batch.
- Severity is produced by inspectable demonstration rules, not generative AI.
- Recommendations are advisory; authorized people retain all containment decisions.
- The optional HTTP server binds only to localhost and is not production-ready.

## Project provenance

This repository began as an AI-assisted educational starter. I used it to practice PowerShell navigation, Python execution, incident-record review, test interpretation, UTC normalization, documentation, and safe escalation boundaries. The repository is presented as a reviewed learning lab rather than original production software or evidence of live security operations.

## Planned improvements

- Add a safe mock-helpdesk input adapter
- Add an analyst-readable Markdown report
- Add more timezone and boundary-condition tests
- Document an additional independently implemented classification rule
- Create a visual case timeline from accepted synthetic events

