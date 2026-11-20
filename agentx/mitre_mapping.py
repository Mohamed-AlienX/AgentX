"""Reviewed mapping: AgentX skills -> MITRE ATT&CK technique IDs.

Each skill maps to techniques its *content* actually performs or teaches.
Process-only skills (reporting, triage, evidence hygiene, detection
engineering) intentionally map to ``[]`` instead of inventing coverage.

Frontmatter is the source of truth at runtime; this module is what the
annotator writes into ``skills/*/SKILL.md`` and what the generator reads.
Keep both in sync via ``scripts/annotate_mitre.py``.
"""

from __future__ import annotations

SKILL_MITRE: dict[str, list[str]] = {
    # Post-exploitation / identity / network
    "ad-attacker": ["T1087.002", "T1558", "T1550", "T1021.002", "T1210", "T1078"],
    "c2-operator": ["T1071", "T1090", "T1572", "T1105"],
    "container-breakout": ["T1611", "T1610", "T1552.007", "T1210"],
    "data-exfiltrator": ["T1048", "T1041", "T1071.004", "T1567"],
    "evasion-specialist": ["T1027", "T1562.001", "T1620", "T1055"],
    "exploit-chainer": ["T1210", "T1068", "T1548"],
    "lateral-movement": ["T1210", "T1021", "T1550", "T1570"],
    "network-attacker": ["T1557", "T1040", "T1210", "T1090"],
    "payload-crafter": ["T1587.001", "T1027", "T1059", "T1105"],
    "persistence-planner": ["T1136", "T1547", "T1053", "T1543", "T1098", "T1505"],
    "privesc-advisor": ["T1068", "T1548", "T1078"],
    # Recon / OSINT / planning
    "ai-recon": ["T1595", "T1592", "T1590"],
    "attack-planner": ["T1595", "T1210"],
    "engagement-planner": ["T1595", "T1591"],
    "offensive-osint": ["T1589", "T1591", "T1590", "T1592", "T1593", "T1596", "T1597", "T1595"],
    "opsec-anonymizer": ["T1090", "T1583", "T1585"],
    "threat-modeler": ["T1591", "T1592"],
    "vuln-scanner": ["T1595", "T1595.002", "T1046"],
    "web2-recon": ["T1595", "T1595.001", "T1590", "T1592"],
    # Hunting: web / API
    "hunt-access-control": ["T1078", "T1530"],
    "hunt-api-misconfig": ["T1190", "T1078"],
    "hunt-business-logic": ["T1190", "T1565"],
    "hunt-client-side": ["T1189", "T1190", "T1059.007", "T1539"],
    "hunt-graphql": ["T1190", "T1530"],
    "hunt-idor": ["T1530", "T1078"],
    "hunt-injection": ["T1190", "T1059"],
    "hunt-race-condition": ["T1190"],
    "hunt-rce": ["T1190", "T1059", "T1505.003"],
    "hunt-shadow-api": ["T1595", "T1190"],
    "hunt-source-leak": ["T1592", "T1552"],
    "hunt-spa-api": ["T1595", "T1190"],
    "hunt-sqli": ["T1190"],
    "hunt-ssrf": ["T1190", "T1552"],
    "hunt-ssrf-xxe": ["T1190", "T1552"],
    "hunt-websocket": ["T1190", "T1539"],
    "hunt-xss": ["T1059.007", "T1189", "T1539"],
    # Hunting: auth / session / identity
    "hunt-auth-bypass": ["T1078", "T1556", "T1550"],
    "hunt-auth-session": ["T1078", "T1539", "T1110", "T1556"],
    "hunt-jwt-crypto": ["T1550.001", "T1078", "T1556"],
    "hunt-mfa-bypass": ["T1078", "T1110", "T1556.006"],
    "hunt-oauth": ["T1078", "T1550", "T1528"],
    "hunt-session": ["T1539", "T1550", "T1078"],
    "password-auditor": ["T1110", "T1552"],
    # Hunting: infra / cloud / supply chain
    "hunt-cicd": ["T1195.002", "T1552"],
    "hunt-cloud-misconfig": ["T1530", "T1552", "T1078.004"],
    "supply-chain-auditor": ["T1195.001", "T1195.002", "T1552"],
    # Hunting: code / crypto / data
    "code-auditor": ["T1190", "T1552", "T1505.003"],
    "crypto-analyzer": ["T1552", "T1550.001", "T1600"],
    "database-attacker": ["T1190", "T1005"],
    "llm-redteam": ["T1190", "T1552"],
    "mobile-pentester": ["T1190", "T1552"],
    "traffic-analyzer": ["T1040", "T1557", "T1552"],
    "reverse-engineer": ["T1027", "T1140"],
    # Hunting: other offense
    "credential-tester": ["T1110", "T1003", "T1552"],
    "phishing-operator": ["T1566", "T1566.002", "T1583.001", "T1585.001", "T1557"],
    "social-engineer": ["T1566", "T1598", "T1585"],
    "wireless-pentester": ["T1557", "T1040"],
    "ctf-solver": ["T1190", "T1059", "T1068"],
    "exploit-guide": ["T1190", "T1068"],
    # Methodology / validation (advisory)
    "bb-methodology": ["T1595", "T1190"],
    "bug-bounty": ["T1595", "T1190", "T1592"],
    "poc-validator": ["T1190", "T1595.002"],
    "security-arsenal": ["T1190", "T1588.002"],
    "swarm-orchestrator": ["T1595", "T1210"],
    # Process-only: deliberately empty (no honest ATT&CK technique)
    "detection-engineer": [],
    "evidence-hygiene": [],
    "fix-verifier": [],
    "report-generator": [],
    "triage-validation": [],
    # --- Imported playbooks (offensive-Agent-s / Claude-BugHunter / pentestcode /
    # --- agentflow / sast-skills / opencode-pentester) ---
    # Imported: web / API hunting
    "recon": ["T1595", "T1595.001", "T1590", "T1592"],
    "supabase": ["T1530", "T1190"],
    "webvuln": ["T1190", "T1189"],
    "api-security": ["T1190", "T1078", "T1550.001"],
    "web-hunter": ["T1190", "T1595.002", "T1189"],
    "hunt-aspnet": ["T1190", "T1505.003", "T1059"],
    "hunt-ato": ["T1078", "T1556", "T1539", "T1528"],
    "hunt-brute-force": ["T1110", "T1078"],
    "hunt-cache-poison": ["T1190", "T1189"],
    "hunt-captcha-bypass": ["T1110", "T1078"],
    "hunt-clickjacking": ["T1189", "T1190"],
    "hunt-csrf": ["T1190", "T1078"],
    "hunt-deserialization": ["T1190", "T1059"],
    "hunt-dom": ["T1059.007", "T1189"],
    "hunt-exceptional-conditions": ["T1190", "T1592"],
    "hunt-file-upload": ["T1505.003", "T1190", "T1059"],
    "hunt-fintech-graphql": ["T1190", "T1078", "T1565"],
    "hunt-forgot-password": ["T1078", "T1110", "T1556"],
    "hunt-grpc": ["T1190", "T1046"],
    "hunt-host-header": ["T1190", "T1189"],
    "hunt-html-injection": ["T1189", "T1190"],
    "hunt-http-smuggling": ["T1190", "T1090"],
    "hunt-k8s": ["T1611", "T1610", "T1552.007"],
    "hunt-laravel": ["T1190", "T1505.003", "T1059"],
    "hunt-ldap": ["T1190", "T1087.002"],
    "hunt-lfi": ["T1190", "T1083", "T1005"],
    "hunt-llm-ai": ["T1190", "T1565", "T1041"],
    "hunt-misc": ["T1190"],
    "hunt-nextjs": ["T1190", "T1059.007"],
    "hunt-nodejs": ["T1190", "T1059", "T1055"],
    "hunt-nosqli": ["T1190", "T1078"],
    "hunt-ntlm-info": ["T1592", "T1087.002", "T1046"],
    "hunt-open-redirect": ["T1189", "T1566.002"],
    "hunt-rag-vector": ["T1190", "T1565", "T1530"],
    "hunt-saml": ["T1556", "T1078", "T1550"],
    "hunt-sharepoint": ["T1190", "T1505.003"],
    "hunt-ssti": ["T1190", "T1059"],
    "hunt-subdomain": ["T1583.001", "T1190"],
    "hunt-tls-network": ["T1592", "T1590", "T1600"],
    "hunt-xxe": ["T1190", "T1005", "T1083"],
    # Imported: recon / OSINT
    "osint-collector": ["T1589", "T1593", "T1596"],
    "osint-methodology": ["T1589", "T1591", "T1590", "T1592", "T1593", "T1596"],
    "recon-advisor": ["T1595", "T1595.001", "T1046", "T1592"],
    "recon-scope-triage": ["T1591", "T1593", "T1596"],
    "supply-chain-attack-recon": ["T1195", "T1195.001", "T1195.002", "T1596"],
    # Imported: cloud / identity / infra
    "cloud-iam-deep": ["T1078.004", "T1098", "T1552"],
    "enterprise-vpn-attack": ["T1133", "T1190"],
    "vmware-vcenter-attack": ["T1190", "T1133"],
    "okta-attack": ["T1078", "T1110", "T1556"],
    "m365-entra-attack": ["T1078", "T1110", "T1556"],
    "svc-database": ["T1190", "T1059", "T1003"],
    "svc-web-server": ["T1190", "T1083", "T1595.002"],
    "svc-pivoting": ["T1090", "T1021", "T1572"],
    "svc-mobile-android": ["T1552", "T1592"],
    "malware-analyst": ["T1027", "T1140", "T1055"],
    "apk-redteam-pipeline": ["T1552", "T1592", "T1528"],
    "ios-redteam-pipeline": ["T1552", "T1592", "T1528"],
    "meme-coin-audit": ["T1190", "T1565"],
    "web3-audit": ["T1190", "T1565"],
    # Imported: business logic
    "bizlogic-hunter": ["T1190", "T1565"],
    # Imported: SAST (static review of the classes above)
    "sast-analysis": ["T1190"],
    "sast-businesslogic": ["T1190", "T1565"],
    "sast-fileupload": ["T1505.003", "T1190"],
    "sast-graphql": ["T1190", "T1078"],
    "sast-hardcodedsecrets": ["T1552", "T1528"],
    "sast-idor": ["T1078", "T1530"],
    "sast-jwt": ["T1550.001", "T1528"],
    "sast-missingauth": ["T1078", "T1190"],
    "sast-pathtraversal": ["T1083", "T1190", "T1005"],
    "sast-rce": ["T1190", "T1059"],
    "sast-sqli": ["T1190", "T1078"],
    "sast-ssrf": ["T1190", "T1090"],
    "sast-ssti": ["T1190", "T1059"],
    "sast-xss": ["T1059.007", "T1189"],
    "sast-xxe": ["T1190", "T1005"],
    # Imported: process-only (deliberately empty)
    "bb-local-toolkit": [],
    "bugcrowd-reporting": [],
    "hunt-dispatch": [],
    "mid-engagement-ir-detection": [],
    "opp-pentest": ["T1595", "T1190"],
    "redteam-mindset": [],
    "redteam-report-template": [],
    "report-writing": [],
    "sast-report": [],
}


def get_mitre_for_skill(skill_name: str) -> list[str]:
    """Return deduplicated MITRE techniques for a skill (order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    for tech in SKILL_MITRE.get(skill_name, []):
        t = tech.upper()
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def mapped_skills() -> list[str]:
    """Skills with at least one technique."""
    return sorted(k for k, v in SKILL_MITRE.items() if v)
