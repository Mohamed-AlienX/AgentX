---
name: bb-local-toolkit
description: >-
  Locate the local offensive tooling this machine already has: where the jhaddix and
  SecLists wordlists, trufflehog, ffuf, dalfox, ghauri and cloned repositories are
  installed. Companion to the bug-bounty orchestrator for the case where a hunt needs a
  real binary or wordlist path before it can run. Use when a hunt needs a local tool and
  you do not know where it lives. Do not use for the hunting methodology itself - use
  bug-bounty.
sources: community, operator_experience
mitre_attack: []
---

# Bug Bounty Local Toolkit

This skill is a **progressive-disclosure index**. The full playbook lives in
`references/`; open only the file whose scope matches the task at hand.

## Reference index

| File | Covers | Open it when |
|------|--------|--------------|
| `references/00-workflow-and-mindset.md` | Workflow spine, the kill-the-theory rule, A->B signal clustering, top-1% mindset | Framing a hunt or deciding whether an idea is worth time |
| `references/01-tooling-and-recon.md` | Go binaries, ffuf patterns, Semgrep, recon pipeline, cloud and API discovery | You need the actual command for a tool or a recon step |
| `references/02-learn-and-hunt.md` | Disclosed-report study, threat modelling, note-taking, subdomain-to-strategy mapping | Preparing before testing, or organising an active hunt |
| `references/03-vuln-checklists.md` | Per-class checklists and bypass tables: IDOR, SSRF, OAuth, upload, race, XSS, SQLi, GraphQL, LLM, cache, smuggling, mobile, CI/CD, SSTI, takeover, ATO, cloud | Testing a specific bug class and you want the checklist and payload table |
| `references/04-validation-and-report.md` | 7-Question Gate, pre-submission gates, CVSS, rejected list, report templates, resources | Deciding whether to submit, or writing the report |

## Related skills

- `bug-bounty` for the routing methodology itself.
- `bb-methodology` for the non-linear hunting phases.
- `security-arsenal` for payload tables.
- `triage-validation` and `report-writing` for the submission gates and the write-up.
