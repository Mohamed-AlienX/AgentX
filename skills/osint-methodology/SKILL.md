---
name: osint-methodology
description: >-
  Full external reconnaissance methodology in five stages: seed discovery, asset
  expansion, enrichment, exposure analysis and reporting. Covers asset-graph discipline,
  confidence upgrades, identity-fabric mapping across Entra, Okta, ADFS, Google and SAML,
  JavaScript and mobile attack surface, cloud exposure, breach correlation,
  detectability-aware probing, WAF and origin discovery, and cryptocurrency or media
  attribution. Use when planning a complete recon programme against an authorized target.
  Do not use for hands-on scanning - use recon-advisor; for a single asset-profile request
  use osint-collector.
sources: community, public_research
version: 2.3
triggers:
  - external recon
  - external red team
  - red team external
  - attack surface management
  - attack surface mapping
  - ASM
  - perimeter recon
  - target reconnaissance
  - bug bounty recon
  - asset discovery
  - footprint
  - attack path
  - identity fabric
  - SSO discovery
  - IdP fingerprinting
  - tenant fingerprinting
  - M365 enumeration
  - Microsoft 365 recon
  - API discovery
  - GraphQL introspection
  - mobile recon
  - APK analysis
  - cloud bucket enumeration
  - bucket enum
  - breach correlation
  - secret leak hunt
  - origin discovery
  - CDN bypass
  - WAF bypass
  - vulnerability prioritization
  - CVE prioritization
  - EPSS
  - CISA KEV
  - phishing infrastructure
  - pretext development
  - bug bounty submission
  - responsible disclosure
  - client report
  - exec summary
  - risk translation
  - confidence upgrade
  - time budget
  - engagement profile
  - asset triage
  - detection-aware probing
  - back-off strategy
  - persona rotation
  - OSINT methodology
  - open source intelligence
  - target profiling
  - data correlation
  - OSINT workflow
  - intelligence collection
  - OSINT campaign
  - recon methodology
  - threat actor investigation
  - attribution
mitre_attack: [T1589, T1591, T1590, T1592, T1593, T1596]
---

# OSINT Methodology — External Red-Team Edition

This skill is a **progressive-disclosure index**. The full playbook lives in
`references/`; open only the file whose scope matches the task at hand.

## Reference index

| File | Covers | Open it when |
|------|--------|--------------|
| `references/01-posture-and-opsec.md` | Authorization posture, confidence levels, output format, citation hygiene, hard rules, OpSec | Before touching a target, and whenever scope or evidence handling is in question |
| `references/02-pipeline-and-assets.md` | Five-stage pipeline, time budgeting, asset graph, severity rubric, pivot modes | Starting an engagement, planning stages, or triaging an asset list |
| `references/03-identity-api-mobile-cloud.md` | Identity fabric, API and auth map, JavaScript, mobile and cloud surface | Enumerating IdPs, APIs, JS bundles, apps or cloud buckets |
| `references/04-investigations.md` | Crypto tracing, image and video forensics, chronolocation, threat actors, people | The target is a person, actor, wallet, image or video rather than a host |
| `references/05-correlation-and-automation.md` | Breach x identity correlation, infrastructure OSINT, automation, synthetic media | Correlating breaches or infrastructure, or automating a corpus run |
| `references/06-reporting-and-ops.md` | Anti-patterns, WAF and origin discovery, CVE prioritization, phishing infra, submission, deliverables | Prioritising CVEs, planning phishing, or writing the client deliverable |

## Related skills

- `osint-collector` for a single passive asset profile.
- `recon-advisor` for active port and service scanning.
- `recon-scope-triage` before testing an ASM dataset for ownership.
- `hunt-*` skills for exploitation of anything found here.
