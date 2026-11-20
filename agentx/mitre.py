"""MITRE ATT&CK Enterprise knowledge for AgentX.

Curated subset covering every tactic a pentest/bug-bounty agent touches.
Loaded at runtime so Navigator layers and coverage docs can be regenerated
offline with no third-party data dependency.

IDs follow Enterprise ATT&CK: ``T####`` and ``T####.###``.
"""

from __future__ import annotations

TACTICS: dict[str, dict[str, str]] = {
    "TA0043": {"name": "Reconnaissance", "url": "https://attack.mitre.org/tactics/TA0043/"},
    "TA0042": {"name": "Resource Development", "url": "https://attack.mitre.org/tactics/TA0042/"},
    "TA0001": {"name": "Initial Access", "url": "https://attack.mitre.org/tactics/TA0001/"},
    "TA0002": {"name": "Execution", "url": "https://attack.mitre.org/tactics/TA0002/"},
    "TA0003": {"name": "Persistence", "url": "https://attack.mitre.org/tactics/TA0003/"},
    "TA0004": {"name": "Privilege Escalation", "url": "https://attack.mitre.org/tactics/TA0004/"},
    "TA0005": {"name": "Defense Evasion", "url": "https://attack.mitre.org/tactics/TA0005/"},
    "TA0006": {"name": "Credential Access", "url": "https://attack.mitre.org/tactics/TA0006/"},
    "TA0007": {"name": "Discovery", "url": "https://attack.mitre.org/tactics/TA0007/"},
    "TA0008": {"name": "Lateral Movement", "url": "https://attack.mitre.org/tactics/TA0008/"},
    "TA0009": {"name": "Collection", "url": "https://attack.mitre.org/tactics/TA0009/"},
    "TA0011": {"name": "Command and Control", "url": "https://attack.mitre.org/tactics/TA0011/"},
    "TA0010": {"name": "Exfiltration", "url": "https://attack.mitre.org/tactics/TA0010/"},
    "TA0040": {"name": "Impact", "url": "https://attack.mitre.org/tactics/TA0040/"},
}

_TECHNIQUE_ROWS: list[tuple[str, str, str]] = [
    ("T1003", "OS Credential Dumping", "TA0006"),
    ("T1005", "Data from Local System", "TA0009"),
    ("T1021", "Remote Services", "TA0008"),
    ("T1021.002", "SMB/Windows Admin Shares", "TA0008"),
    ("T1027", "Obfuscated Files or Information", "TA0005"),
    ("T1040", "Network Sniffing", "TA0006"),
    ("T1041", "Exfiltration Over C2 Channel", "TA0010"),
    ("T1046", "Network Service Discovery", "TA0007"),
    ("T1048", "Exfiltration Over Alternative Protocol", "TA0010"),
    ("T1053", "Scheduled Task/Job", "TA0003"),
    ("T1055", "Process Injection", "TA0005"),
    ("T1059", "Command and Scripting Interpreter", "TA0002"),
    ("T1059.007", "JavaScript", "TA0002"),
    ("T1068", "Exploitation for Privilege Escalation", "TA0004"),
    ("T1071", "Application Layer Protocol", "TA0011"),
    ("T1071.004", "DNS", "TA0011"),
    ("T1078", "Valid Accounts", "TA0001"),
    ("T1078.004", "Cloud Accounts", "TA0001"),
    ("T1083", "File and Directory Discovery", "TA0007"),
    ("T1087", "Account Discovery", "TA0007"),
    ("T1087.002", "Domain Account", "TA0007"),
    ("T1090", "Proxy", "TA0011"),
    ("T1098", "Account Manipulation", "TA0003"),
    ("T1105", "Ingress Tool Transfer", "TA0011"),
    ("T1110", "Brute Force", "TA0006"),
    ("T1136", "Create Account", "TA0003"),
    ("T1133", "External Remote Services", "TA0001"),
    ("T1140", "Deobfuscate/Decode Files or Information", "TA0005"),
    ("T1189", "Drive-by Compromise", "TA0001"),
    ("T1190", "Exploit Public-Facing Application", "TA0001"),
    ("T1195", "Supply Chain Compromise", "TA0001"),
    ("T1195.001", "Compromise Software Dependencies and Development Tools", "TA0001"),
    ("T1195.002", "Compromise Software Supply Chain", "TA0001"),
    ("T1200", "Hardware Additions", "TA0001"),
    ("T1210", "Exploitation of Remote Services", "TA0008"),
    ("T1213", "Data from Information Repositories", "TA0009"),
    ("T1486", "Data Encrypted for Impact", "TA0040"),
    ("T1498", "Network Denial of Service", "TA0040"),
    ("T1505", "Server Software Component", "TA0003"),
    ("T1505.003", "Web Shell", "TA0003"),
    ("T1528", "Steal Application Access Token", "TA0006"),
    ("T1530", "Data from Cloud Storage", "TA0009"),
    ("T1539", "Steal Web Session Cookie", "TA0006"),
    ("T1543", "Create or Modify System Process", "TA0003"),
    ("T1547", "Boot or Logon Autostart Execution", "TA0003"),
    ("T1548", "Abuse Elevation Control Mechanism", "TA0004"),
    ("T1550", "Use Alternate Authentication Material", "TA0006"),
    ("T1550.001", "Application Access Token", "TA0006"),
    ("T1552", "Unsecured Credentials", "TA0006"),
    ("T1552.007", "Container API", "TA0006"),
    ("T1556", "Modify Authentication Process", "TA0006"),
    ("T1556.006", "Multi-Factor Authentication", "TA0006"),
    ("T1557", "Adversary-in-the-Middle", "TA0006"),
    ("T1558", "Steal or Forge Kerberos Tickets", "TA0006"),
    ("T1565", "Data Manipulation", "TA0040"),
    ("T1566", "Phishing", "TA0001"),
    ("T1566.002", "Spearphishing Link", "TA0001"),
    ("T1567", "Exfiltration Over Web Service", "TA0010"),
    ("T1562", "Impair Defenses", "TA0005"),
    ("T1562.001", "Disable or Modify Tools", "TA0005"),
    ("T1570", "Lateral Tool Transfer", "TA0008"),
    ("T1572", "Protocol Tunneling", "TA0011"),
    ("T1583", "Acquire Infrastructure", "TA0042"),
    ("T1583.001", "Domains", "TA0042"),
    ("T1585", "Establish Accounts", "TA0042"),
    ("T1585.001", "Social Media Accounts", "TA0042"),
    ("T1587.001", "Malware", "TA0042"),
    ("T1588.002", "Tool", "TA0042"),
    ("T1589", "Gather Victim Identity Information", "TA0043"),
    ("T1590", "Gather Victim Network Information", "TA0043"),
    ("T1591", "Gather Victim Org Information", "TA0043"),
    ("T1592", "Gather Victim Host Information", "TA0043"),
    ("T1593", "Search Open Websites/Domains", "TA0043"),
    ("T1595", "Active Scanning", "TA0043"),
    ("T1595.001", "Scanning IP Blocks", "TA0043"),
    ("T1595.002", "Vulnerability Scanning", "TA0043"),
    ("T1596", "Search Open Technical Databases", "TA0043"),
    ("T1597", "Search Closed Sources", "TA0043"),
    ("T1598", "Phishing for Information", "TA0043"),
    ("T1600", "Weaken Encryption", "TA0005"),
    ("T1610", "Deploy Container", "TA0002"),
    ("T1611", "Escape to Host", "TA0004"),
    ("T1620", "Reflective Code Loading", "TA0005"),
]


def _build() -> dict[str, dict[str, str]]:
    techniques: dict[str, dict[str, str]] = {}
    for tech_id, name, tactic in _TECHNIQUE_ROWS:
        slug = tech_id.replace(".", "/")
        techniques[tech_id] = {
            "name": name,
            "tactic": tactic,
            "url": f"https://attack.mitre.org/techniques/{slug}/",
        }
    return techniques


TECHNIQUES: dict[str, dict[str, str]] = _build()


def get_technique(tech_id: str) -> dict[str, str] | None:
    """Return technique metadata or None if unknown."""
    return TECHNIQUES.get(tech_id.upper())


def technique_url(tech_id: str) -> str:
    """Canonical ATT&CK URL for a technique ID."""
    tech = get_technique(tech_id)
    if tech:
        return tech["url"]
    return f"https://attack.mitre.org/techniques/{tech_id.upper().replace('.', '/')}/"


def tactic_of(tech_id: str) -> str:
    """Tactic ID for a technique (empty string if unknown)."""
    tech = get_technique(tech_id)
    return tech["tactic"] if tech else ""


def tactic_name(tactic_id: str) -> str:
    """Human-readable tactic name."""
    return TACTICS.get(tactic_id, {}).get("name", tactic_id)
