# MITRE ATT&CK Coverage (AgentX Skills)

- Skills total: 153
- Skills mapped to ≥1 technique: 140
- Techniques covered: 77
- Navigator layer: [mappings/attack-navigator-layer.json](mappings/attack-navigator-layer.json)

> Process-only skills are intentionally unmapped rather than given invented technique IDs.

## Coverage by Tactic

| Tactic | Technique | Name | Skills |
|---|---|---|---|
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1589](https://attack.mitre.org/techniques/T1589/) | Gather Victim Identity Information | offensive-osint, osint-collector, osint-methodology |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1590](https://attack.mitre.org/techniques/T1590/) | Gather Victim Network Information | ai-recon, hunt-tls-network, offensive-osint, osint-methodology, recon, web2-recon |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1591](https://attack.mitre.org/techniques/T1591/) | Gather Victim Org Information | engagement-planner, offensive-osint, osint-methodology, recon-scope-triage, threat-modeler |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | ai-recon, apk-redteam-pipeline, bug-bounty, hunt-exceptional-conditions, hunt-ntlm-info, hunt-source-leak, hunt-tls-network, ios-redteam-pipeline, offensive-osint, osint-methodology, recon, recon-advisor, svc-mobile-android, threat-modeler, web2-recon |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1593](https://attack.mitre.org/techniques/T1593/) | Search Open Websites/Domains | offensive-osint, osint-collector, osint-methodology, recon-scope-triage |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning | ai-recon, attack-planner, bb-methodology, bug-bounty, engagement-planner, hunt-shadow-api, hunt-spa-api, offensive-osint, opp-pentest, recon, recon-advisor, swarm-orchestrator, vuln-scanner, web2-recon |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Scanning IP Blocks | recon, recon-advisor, web2-recon |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Vulnerability Scanning | poc-validator, svc-web-server, vuln-scanner, web-hunter |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1596](https://attack.mitre.org/techniques/T1596/) | Search Open Technical Databases | offensive-osint, osint-collector, osint-methodology, recon-scope-triage, supply-chain-attack-recon |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1597](https://attack.mitre.org/techniques/T1597/) | Search Closed Sources | offensive-osint |
| [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [T1598](https://attack.mitre.org/techniques/T1598/) | Phishing for Information | social-engineer |
| [Resource Development](https://attack.mitre.org/tactics/TA0042/) | [T1583](https://attack.mitre.org/techniques/T1583/) | Acquire Infrastructure | opsec-anonymizer |
| [Resource Development](https://attack.mitre.org/tactics/TA0042/) | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Domains | hunt-subdomain, phishing-operator |
| [Resource Development](https://attack.mitre.org/tactics/TA0042/) | [T1585](https://attack.mitre.org/techniques/T1585/) | Establish Accounts | opsec-anonymizer, social-engineer |
| [Resource Development](https://attack.mitre.org/tactics/TA0042/) | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Social Media Accounts | phishing-operator |
| [Resource Development](https://attack.mitre.org/tactics/TA0042/) | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Malware | payload-crafter |
| [Resource Development](https://attack.mitre.org/tactics/TA0042/) | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Tool | security-arsenal |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | ad-attacker, api-security, hunt-access-control, hunt-api-misconfig, hunt-ato, hunt-auth-bypass, hunt-auth-session, hunt-brute-force, hunt-captcha-bypass, hunt-csrf, hunt-fintech-graphql, hunt-forgot-password, hunt-idor, hunt-jwt-crypto, hunt-mfa-bypass, hunt-nosqli, hunt-oauth, hunt-saml, hunt-session, m365-entra-attack, okta-attack, privesc-advisor, sast-graphql, sast-idor, sast-missingauth, sast-sqli |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | cloud-iam-deep, hunt-cloud-misconfig |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | enterprise-vpn-attack, vmware-vcenter-attack |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1189](https://attack.mitre.org/techniques/T1189/) | Drive-by Compromise | hunt-cache-poison, hunt-clickjacking, hunt-client-side, hunt-dom, hunt-host-header, hunt-html-injection, hunt-open-redirect, hunt-xss, sast-xss, web-hunter, webvuln |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | api-security, bb-methodology, bizlogic-hunter, bug-bounty, code-auditor, ctf-solver, database-attacker, enterprise-vpn-attack, exploit-guide, hunt-api-misconfig, hunt-aspnet, hunt-business-logic, hunt-cache-poison, hunt-clickjacking, hunt-client-side, hunt-csrf, hunt-deserialization, hunt-exceptional-conditions, hunt-file-upload, hunt-fintech-graphql, hunt-graphql, hunt-grpc, hunt-host-header, hunt-html-injection, hunt-http-smuggling, hunt-injection, hunt-laravel, hunt-ldap, hunt-lfi, hunt-llm-ai, hunt-misc, hunt-nextjs, hunt-nodejs, hunt-nosqli, hunt-race-condition, hunt-rag-vector, hunt-rce, hunt-shadow-api, hunt-sharepoint, hunt-spa-api, hunt-sqli, hunt-ssrf, hunt-ssrf-xxe, hunt-ssti, hunt-subdomain, hunt-websocket, hunt-xxe, llm-redteam, meme-coin-audit, mobile-pentester, opp-pentest, poc-validator, sast-analysis, sast-businesslogic, sast-fileupload, sast-graphql, sast-missingauth, sast-pathtraversal, sast-rce, sast-sqli, sast-ssrf, sast-ssti, sast-xxe, security-arsenal, supabase, svc-database, svc-web-server, vmware-vcenter-attack, web-hunter, web3-audit, webvuln |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise | supply-chain-attack-recon |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Compromise Software Dependencies and Development Tools | supply-chain-attack-recon, supply-chain-auditor |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Compromise Software Supply Chain | hunt-cicd, supply-chain-attack-recon, supply-chain-auditor |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | phishing-operator, social-engineer |
| [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | hunt-open-redirect, phishing-operator |
| [Execution](https://attack.mitre.org/tactics/TA0002/) | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | ctf-solver, hunt-aspnet, hunt-deserialization, hunt-file-upload, hunt-injection, hunt-laravel, hunt-nodejs, hunt-rce, hunt-ssti, payload-crafter, sast-rce, sast-ssti, svc-database |
| [Execution](https://attack.mitre.org/tactics/TA0002/) | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | JavaScript | hunt-client-side, hunt-dom, hunt-nextjs, hunt-xss, sast-xss |
| [Execution](https://attack.mitre.org/tactics/TA0002/) | [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container | container-breakout, hunt-k8s |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | persistence-planner |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | cloud-iam-deep, persistence-planner |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | persistence-planner |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1505](https://attack.mitre.org/techniques/T1505/) | Server Software Component | persistence-planner |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | code-auditor, hunt-aspnet, hunt-file-upload, hunt-laravel, hunt-rce, hunt-sharepoint, sast-fileupload |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | persistence-planner |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | persistence-planner |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | ctf-solver, exploit-chainer, exploit-guide, privesc-advisor |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | exploit-chainer, privesc-advisor |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | container-breakout, hunt-k8s |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | evasion-specialist, malware-analyst, payload-crafter, reverse-engineer |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | evasion-specialist, hunt-nodejs, malware-analyst |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | malware-analyst, reverse-engineer |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | evasion-specialist |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1600](https://attack.mitre.org/techniques/T1600/) | Weaken Encryption | crypto-analyzer, hunt-tls-network |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1620](https://attack.mitre.org/techniques/T1620/) | Reflective Code Loading | evasion-specialist |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | credential-tester, svc-database |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | network-attacker, traffic-analyzer, wireless-pentester |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | credential-tester, hunt-auth-session, hunt-brute-force, hunt-captcha-bypass, hunt-forgot-password, hunt-mfa-bypass, m365-entra-attack, okta-attack, password-auditor |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | apk-redteam-pipeline, hunt-ato, hunt-oauth, ios-redteam-pipeline, sast-hardcodedsecrets, sast-jwt |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1539](https://attack.mitre.org/techniques/T1539/) | Steal Web Session Cookie | hunt-ato, hunt-auth-session, hunt-client-side, hunt-session, hunt-websocket, hunt-xss |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | ad-attacker, hunt-auth-bypass, hunt-oauth, hunt-saml, hunt-session, lateral-movement |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Application Access Token | api-security, crypto-analyzer, hunt-jwt-crypto, sast-jwt |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | apk-redteam-pipeline, cloud-iam-deep, code-auditor, credential-tester, crypto-analyzer, hunt-cicd, hunt-cloud-misconfig, hunt-source-leak, hunt-ssrf, hunt-ssrf-xxe, ios-redteam-pipeline, llm-redteam, mobile-pentester, password-auditor, sast-hardcodedsecrets, supply-chain-auditor, svc-mobile-android, traffic-analyzer |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1552.007](https://attack.mitre.org/techniques/T1552/007/) | Container API | container-breakout, hunt-k8s |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1556](https://attack.mitre.org/techniques/T1556/) | Modify Authentication Process | hunt-ato, hunt-auth-bypass, hunt-auth-session, hunt-forgot-password, hunt-jwt-crypto, hunt-saml, m365-entra-attack, okta-attack |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1556.006](https://attack.mitre.org/techniques/T1556/006/) | Multi-Factor Authentication | hunt-mfa-bypass |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | network-attacker, phishing-operator, traffic-analyzer, wireless-pentester |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | ad-attacker |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | hunt-grpc, hunt-ntlm-info, recon-advisor, vuln-scanner |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | hunt-lfi, hunt-xxe, sast-pathtraversal, svc-web-server |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | ad-attacker, hunt-ldap, hunt-ntlm-info |
| [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | lateral-movement, svc-pivoting |
| [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | ad-attacker |
| [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services | ad-attacker, attack-planner, container-breakout, exploit-chainer, lateral-movement, network-attacker, swarm-orchestrator |
| [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Tool Transfer | lateral-movement |
| [Collection](https://attack.mitre.org/tactics/TA0009/) | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | database-attacker, hunt-lfi, hunt-xxe, sast-pathtraversal, sast-xxe |
| [Collection](https://attack.mitre.org/tactics/TA0009/) | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | hunt-access-control, hunt-cloud-misconfig, hunt-graphql, hunt-idor, hunt-rag-vector, sast-idor, supabase |
| [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | c2-operator |
| [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | data-exfiltrator |
| [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | c2-operator, hunt-http-smuggling, network-attacker, opsec-anonymizer, sast-ssrf, svc-pivoting |
| [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | c2-operator, payload-crafter |
| [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | c2-operator, svc-pivoting |
| [Exfiltration](https://attack.mitre.org/tactics/TA0010/) | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | data-exfiltrator, hunt-llm-ai |
| [Exfiltration](https://attack.mitre.org/tactics/TA0010/) | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | data-exfiltrator |
| [Exfiltration](https://attack.mitre.org/tactics/TA0010/) | [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | data-exfiltrator |
| [Impact](https://attack.mitre.org/tactics/TA0040/) | [T1565](https://attack.mitre.org/techniques/T1565/) | Data Manipulation | bizlogic-hunter, hunt-business-logic, hunt-fintech-graphql, hunt-llm-ai, hunt-rag-vector, meme-coin-audit, sast-businesslogic, web3-audit |

## Per-Skill Mapping

| Skill | Category | Techniques |
|---|---|---|
| ad-attacker | - | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) [T1558](https://attack.mitre.org/techniques/T1558/) [T1550](https://attack.mitre.org/techniques/T1550/) [T1021.002](https://attack.mitre.org/techniques/T1021/002/) [T1210](https://attack.mitre.org/techniques/T1210/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| ai-recon | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1592](https://attack.mitre.org/techniques/T1592/) [T1590](https://attack.mitre.org/techniques/T1590/) |
| api-security | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1078](https://attack.mitre.org/techniques/T1078/) [T1550.001](https://attack.mitre.org/techniques/T1550/001/) |
| apk-redteam-pipeline | - | [T1552](https://attack.mitre.org/techniques/T1552/) [T1592](https://attack.mitre.org/techniques/T1592/) [T1528](https://attack.mitre.org/techniques/T1528/) |
| attack-planner | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1210](https://attack.mitre.org/techniques/T1210/) |
| bb-local-toolkit | - | — |
| bb-methodology | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| bizlogic-hunter | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1565](https://attack.mitre.org/techniques/T1565/) |
| bug-bounty | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1190](https://attack.mitre.org/techniques/T1190/) [T1592](https://attack.mitre.org/techniques/T1592/) |
| bugcrowd-reporting | - | — |
| c2-operator | post-exploitation | [T1071](https://attack.mitre.org/techniques/T1071/) [T1090](https://attack.mitre.org/techniques/T1090/) [T1572](https://attack.mitre.org/techniques/T1572/) [T1105](https://attack.mitre.org/techniques/T1105/) |
| cloud-iam-deep | - | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) [T1098](https://attack.mitre.org/techniques/T1098/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| code-auditor | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1552](https://attack.mitre.org/techniques/T1552/) [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| container-breakout | - | [T1611](https://attack.mitre.org/techniques/T1611/) [T1610](https://attack.mitre.org/techniques/T1610/) [T1552.007](https://attack.mitre.org/techniques/T1552/007/) [T1210](https://attack.mitre.org/techniques/T1210/) |
| credential-tester | hunting | [T1110](https://attack.mitre.org/techniques/T1110/) [T1003](https://attack.mitre.org/techniques/T1003/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| crypto-analyzer | hunting | [T1552](https://attack.mitre.org/techniques/T1552/) [T1550.001](https://attack.mitre.org/techniques/T1550/001/) [T1600](https://attack.mitre.org/techniques/T1600/) |
| ctf-solver | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) [T1068](https://attack.mitre.org/techniques/T1068/) |
| data-exfiltrator | post-exploitation | [T1048](https://attack.mitre.org/techniques/T1048/) [T1041](https://attack.mitre.org/techniques/T1041/) [T1071.004](https://attack.mitre.org/techniques/T1071/004/) [T1567](https://attack.mitre.org/techniques/T1567/) |
| database-attacker | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1005](https://attack.mitre.org/techniques/T1005/) |
| detection-engineer | - | — |
| engagement-planner | methodology | [T1595](https://attack.mitre.org/techniques/T1595/) [T1591](https://attack.mitre.org/techniques/T1591/) |
| enterprise-vpn-attack | - | [T1133](https://attack.mitre.org/techniques/T1133/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| evasion-specialist | post-exploitation | [T1027](https://attack.mitre.org/techniques/T1027/) [T1562.001](https://attack.mitre.org/techniques/T1562/001/) [T1620](https://attack.mitre.org/techniques/T1620/) [T1055](https://attack.mitre.org/techniques/T1055/) |
| evidence-hygiene | - | — |
| exploit-chainer | - | [T1210](https://attack.mitre.org/techniques/T1210/) [T1068](https://attack.mitre.org/techniques/T1068/) [T1548](https://attack.mitre.org/techniques/T1548/) |
| exploit-guide | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1068](https://attack.mitre.org/techniques/T1068/) |
| fix-verifier | validation | — |
| hunt-access-control | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1530](https://attack.mitre.org/techniques/T1530/) |
| hunt-api-misconfig | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| hunt-aspnet | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1505.003](https://attack.mitre.org/techniques/T1505/003/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| hunt-ato | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1556](https://attack.mitre.org/techniques/T1556/) [T1539](https://attack.mitre.org/techniques/T1539/) [T1528](https://attack.mitre.org/techniques/T1528/) |
| hunt-auth-bypass | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1556](https://attack.mitre.org/techniques/T1556/) [T1550](https://attack.mitre.org/techniques/T1550/) |
| hunt-auth-session | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1539](https://attack.mitre.org/techniques/T1539/) [T1110](https://attack.mitre.org/techniques/T1110/) [T1556](https://attack.mitre.org/techniques/T1556/) |
| hunt-brute-force | - | [T1110](https://attack.mitre.org/techniques/T1110/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| hunt-business-logic | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1565](https://attack.mitre.org/techniques/T1565/) |
| hunt-cache-poison | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1189](https://attack.mitre.org/techniques/T1189/) |
| hunt-captcha-bypass | - | [T1110](https://attack.mitre.org/techniques/T1110/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| hunt-cicd | - | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| hunt-clickjacking | - | [T1189](https://attack.mitre.org/techniques/T1189/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-client-side | - | [T1189](https://attack.mitre.org/techniques/T1189/) [T1190](https://attack.mitre.org/techniques/T1190/) [T1059.007](https://attack.mitre.org/techniques/T1059/007/) [T1539](https://attack.mitre.org/techniques/T1539/) |
| hunt-cloud-misconfig | - | [T1530](https://attack.mitre.org/techniques/T1530/) [T1552](https://attack.mitre.org/techniques/T1552/) [T1078.004](https://attack.mitre.org/techniques/T1078/004/) |
| hunt-csrf | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| hunt-deserialization | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| hunt-dispatch | - | — |
| hunt-dom | - | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) [T1189](https://attack.mitre.org/techniques/T1189/) |
| hunt-exceptional-conditions | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1592](https://attack.mitre.org/techniques/T1592/) |
| hunt-file-upload | - | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| hunt-fintech-graphql | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1078](https://attack.mitre.org/techniques/T1078/) [T1565](https://attack.mitre.org/techniques/T1565/) |
| hunt-forgot-password | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1110](https://attack.mitre.org/techniques/T1110/) [T1556](https://attack.mitre.org/techniques/T1556/) |
| hunt-graphql | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1530](https://attack.mitre.org/techniques/T1530/) |
| hunt-grpc | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1046](https://attack.mitre.org/techniques/T1046/) |
| hunt-host-header | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1189](https://attack.mitre.org/techniques/T1189/) |
| hunt-html-injection | - | [T1189](https://attack.mitre.org/techniques/T1189/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-http-smuggling | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1090](https://attack.mitre.org/techniques/T1090/) |
| hunt-idor | - | [T1530](https://attack.mitre.org/techniques/T1530/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| hunt-injection | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| hunt-jwt-crypto | - | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) [T1078](https://attack.mitre.org/techniques/T1078/) [T1556](https://attack.mitre.org/techniques/T1556/) |
| hunt-k8s | - | [T1611](https://attack.mitre.org/techniques/T1611/) [T1610](https://attack.mitre.org/techniques/T1610/) [T1552.007](https://attack.mitre.org/techniques/T1552/007/) |
| hunt-laravel | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1505.003](https://attack.mitre.org/techniques/T1505/003/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| hunt-ldap | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| hunt-lfi | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1083](https://attack.mitre.org/techniques/T1083/) [T1005](https://attack.mitre.org/techniques/T1005/) |
| hunt-llm-ai | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1565](https://attack.mitre.org/techniques/T1565/) [T1041](https://attack.mitre.org/techniques/T1041/) |
| hunt-mfa-bypass | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1110](https://attack.mitre.org/techniques/T1110/) [T1556.006](https://attack.mitre.org/techniques/T1556/006/) |
| hunt-misc | - | [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-nextjs | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059.007](https://attack.mitre.org/techniques/T1059/007/) |
| hunt-nodejs | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) [T1055](https://attack.mitre.org/techniques/T1055/) |
| hunt-nosqli | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| hunt-ntlm-info | - | [T1592](https://attack.mitre.org/techniques/T1592/) [T1087.002](https://attack.mitre.org/techniques/T1087/002/) [T1046](https://attack.mitre.org/techniques/T1046/) |
| hunt-oauth | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1550](https://attack.mitre.org/techniques/T1550/) [T1528](https://attack.mitre.org/techniques/T1528/) |
| hunt-open-redirect | - | [T1189](https://attack.mitre.org/techniques/T1189/) [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| hunt-race-condition | - | [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-rag-vector | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1565](https://attack.mitre.org/techniques/T1565/) [T1530](https://attack.mitre.org/techniques/T1530/) |
| hunt-rce | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| hunt-saml | - | [T1556](https://attack.mitre.org/techniques/T1556/) [T1078](https://attack.mitre.org/techniques/T1078/) [T1550](https://attack.mitre.org/techniques/T1550/) |
| hunt-session | - | [T1539](https://attack.mitre.org/techniques/T1539/) [T1550](https://attack.mitre.org/techniques/T1550/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| hunt-shadow-api | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-sharepoint | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| hunt-source-leak | - | [T1592](https://attack.mitre.org/techniques/T1592/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| hunt-spa-api | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-sqli | - | [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-ssrf | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| hunt-ssrf-xxe | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| hunt-ssti | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| hunt-subdomain | - | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| hunt-tls-network | - | [T1592](https://attack.mitre.org/techniques/T1592/) [T1590](https://attack.mitre.org/techniques/T1590/) [T1600](https://attack.mitre.org/techniques/T1600/) |
| hunt-websocket | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1539](https://attack.mitre.org/techniques/T1539/) |
| hunt-xss | - | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) [T1189](https://attack.mitre.org/techniques/T1189/) [T1539](https://attack.mitre.org/techniques/T1539/) |
| hunt-xxe | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1005](https://attack.mitre.org/techniques/T1005/) [T1083](https://attack.mitre.org/techniques/T1083/) |
| ios-redteam-pipeline | - | [T1552](https://attack.mitre.org/techniques/T1552/) [T1592](https://attack.mitre.org/techniques/T1592/) [T1528](https://attack.mitre.org/techniques/T1528/) |
| lateral-movement | - | [T1210](https://attack.mitre.org/techniques/T1210/) [T1021](https://attack.mitre.org/techniques/T1021/) [T1550](https://attack.mitre.org/techniques/T1550/) [T1570](https://attack.mitre.org/techniques/T1570/) |
| llm-redteam | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| m365-entra-attack | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1110](https://attack.mitre.org/techniques/T1110/) [T1556](https://attack.mitre.org/techniques/T1556/) |
| malware-analyst | - | [T1027](https://attack.mitre.org/techniques/T1027/) [T1140](https://attack.mitre.org/techniques/T1140/) [T1055](https://attack.mitre.org/techniques/T1055/) |
| meme-coin-audit | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1565](https://attack.mitre.org/techniques/T1565/) |
| mid-engagement-ir-detection | - | — |
| mobile-pentester | infrastructure | [T1190](https://attack.mitre.org/techniques/T1190/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| network-attacker | - | [T1557](https://attack.mitre.org/techniques/T1557/) [T1040](https://attack.mitre.org/techniques/T1040/) [T1210](https://attack.mitre.org/techniques/T1210/) [T1090](https://attack.mitre.org/techniques/T1090/) |
| offensive-osint | - | [T1589](https://attack.mitre.org/techniques/T1589/) [T1591](https://attack.mitre.org/techniques/T1591/) [T1590](https://attack.mitre.org/techniques/T1590/) [T1592](https://attack.mitre.org/techniques/T1592/) [T1593](https://attack.mitre.org/techniques/T1593/) [T1596](https://attack.mitre.org/techniques/T1596/) [T1597](https://attack.mitre.org/techniques/T1597/) [T1595](https://attack.mitre.org/techniques/T1595/) |
| okta-attack | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1110](https://attack.mitre.org/techniques/T1110/) [T1556](https://attack.mitre.org/techniques/T1556/) |
| opp-pentest | methodology | [T1595](https://attack.mitre.org/techniques/T1595/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| opsec-anonymizer | methodology | [T1090](https://attack.mitre.org/techniques/T1090/) [T1583](https://attack.mitre.org/techniques/T1583/) [T1585](https://attack.mitre.org/techniques/T1585/) |
| osint-collector | - | [T1589](https://attack.mitre.org/techniques/T1589/) [T1593](https://attack.mitre.org/techniques/T1593/) [T1596](https://attack.mitre.org/techniques/T1596/) |
| osint-methodology | - | [T1589](https://attack.mitre.org/techniques/T1589/) [T1591](https://attack.mitre.org/techniques/T1591/) [T1590](https://attack.mitre.org/techniques/T1590/) [T1592](https://attack.mitre.org/techniques/T1592/) [T1593](https://attack.mitre.org/techniques/T1593/) [T1596](https://attack.mitre.org/techniques/T1596/) |
| password-auditor | validation | [T1110](https://attack.mitre.org/techniques/T1110/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| payload-crafter | - | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) [T1027](https://attack.mitre.org/techniques/T1027/) [T1059](https://attack.mitre.org/techniques/T1059/) [T1105](https://attack.mitre.org/techniques/T1105/) |
| persistence-planner | post-exploitation | [T1136](https://attack.mitre.org/techniques/T1136/) [T1547](https://attack.mitre.org/techniques/T1547/) [T1053](https://attack.mitre.org/techniques/T1053/) [T1543](https://attack.mitre.org/techniques/T1543/) [T1098](https://attack.mitre.org/techniques/T1098/) [T1505](https://attack.mitre.org/techniques/T1505/) |
| phishing-operator | infrastructure | [T1566](https://attack.mitre.org/techniques/T1566/) [T1566.002](https://attack.mitre.org/techniques/T1566/002/) [T1583.001](https://attack.mitre.org/techniques/T1583/001/) [T1585.001](https://attack.mitre.org/techniques/T1585/001/) [T1557](https://attack.mitre.org/techniques/T1557/) |
| poc-validator | validation | [T1190](https://attack.mitre.org/techniques/T1190/) [T1595.002](https://attack.mitre.org/techniques/T1595/002/) |
| privesc-advisor | - | [T1068](https://attack.mitre.org/techniques/T1068/) [T1548](https://attack.mitre.org/techniques/T1548/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| recon | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1595.001](https://attack.mitre.org/techniques/T1595/001/) [T1590](https://attack.mitre.org/techniques/T1590/) [T1592](https://attack.mitre.org/techniques/T1592/) |
| recon-advisor | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1595.001](https://attack.mitre.org/techniques/T1595/001/) [T1046](https://attack.mitre.org/techniques/T1046/) [T1592](https://attack.mitre.org/techniques/T1592/) |
| recon-scope-triage | - | [T1591](https://attack.mitre.org/techniques/T1591/) [T1593](https://attack.mitre.org/techniques/T1593/) [T1596](https://attack.mitre.org/techniques/T1596/) |
| redteam-mindset | - | — |
| redteam-report-template | - | — |
| report-generator | reporting | — |
| report-writing | - | — |
| reverse-engineer | post-exploitation | [T1027](https://attack.mitre.org/techniques/T1027/) [T1140](https://attack.mitre.org/techniques/T1140/) |
| sast-analysis | - | [T1190](https://attack.mitre.org/techniques/T1190/) |
| sast-businesslogic | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1565](https://attack.mitre.org/techniques/T1565/) |
| sast-fileupload | - | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| sast-graphql | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| sast-hardcodedsecrets | - | [T1552](https://attack.mitre.org/techniques/T1552/) [T1528](https://attack.mitre.org/techniques/T1528/) |
| sast-idor | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1530](https://attack.mitre.org/techniques/T1530/) |
| sast-jwt | - | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) [T1528](https://attack.mitre.org/techniques/T1528/) |
| sast-missingauth | - | [T1078](https://attack.mitre.org/techniques/T1078/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| sast-pathtraversal | - | [T1083](https://attack.mitre.org/techniques/T1083/) [T1190](https://attack.mitre.org/techniques/T1190/) [T1005](https://attack.mitre.org/techniques/T1005/) |
| sast-rce | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| sast-report | - | — |
| sast-sqli | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1078](https://attack.mitre.org/techniques/T1078/) |
| sast-ssrf | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1090](https://attack.mitre.org/techniques/T1090/) |
| sast-ssti | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) |
| sast-xss | - | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) [T1189](https://attack.mitre.org/techniques/T1189/) |
| sast-xxe | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1005](https://attack.mitre.org/techniques/T1005/) |
| security-arsenal | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1588.002](https://attack.mitre.org/techniques/T1588/002/) |
| social-engineer | infrastructure | [T1566](https://attack.mitre.org/techniques/T1566/) [T1598](https://attack.mitre.org/techniques/T1598/) [T1585](https://attack.mitre.org/techniques/T1585/) |
| supabase | - | [T1530](https://attack.mitre.org/techniques/T1530/) [T1190](https://attack.mitre.org/techniques/T1190/) |
| supply-chain-attack-recon | - | [T1195](https://attack.mitre.org/techniques/T1195/) [T1195.001](https://attack.mitre.org/techniques/T1195/001/) [T1195.002](https://attack.mitre.org/techniques/T1195/002/) [T1596](https://attack.mitre.org/techniques/T1596/) |
| supply-chain-auditor | hunting | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) [T1195.002](https://attack.mitre.org/techniques/T1195/002/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| svc-database | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1059](https://attack.mitre.org/techniques/T1059/) [T1003](https://attack.mitre.org/techniques/T1003/) |
| svc-mobile-android | - | [T1552](https://attack.mitre.org/techniques/T1552/) [T1592](https://attack.mitre.org/techniques/T1592/) |
| svc-pivoting | - | [T1090](https://attack.mitre.org/techniques/T1090/) [T1021](https://attack.mitre.org/techniques/T1021/) [T1572](https://attack.mitre.org/techniques/T1572/) |
| svc-web-server | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1083](https://attack.mitre.org/techniques/T1083/) [T1595.002](https://attack.mitre.org/techniques/T1595/002/) |
| swarm-orchestrator | methodology | [T1595](https://attack.mitre.org/techniques/T1595/) [T1210](https://attack.mitre.org/techniques/T1210/) |
| threat-modeler | methodology | [T1591](https://attack.mitre.org/techniques/T1591/) [T1592](https://attack.mitre.org/techniques/T1592/) |
| traffic-analyzer | infrastructure | [T1040](https://attack.mitre.org/techniques/T1040/) [T1557](https://attack.mitre.org/techniques/T1557/) [T1552](https://attack.mitre.org/techniques/T1552/) |
| triage-validation | - | — |
| vmware-vcenter-attack | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1133](https://attack.mitre.org/techniques/T1133/) |
| vuln-scanner | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1595.002](https://attack.mitre.org/techniques/T1595/002/) [T1046](https://attack.mitre.org/techniques/T1046/) |
| web-hunter | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1595.002](https://attack.mitre.org/techniques/T1595/002/) [T1189](https://attack.mitre.org/techniques/T1189/) |
| web2-recon | - | [T1595](https://attack.mitre.org/techniques/T1595/) [T1595.001](https://attack.mitre.org/techniques/T1595/001/) [T1590](https://attack.mitre.org/techniques/T1590/) [T1592](https://attack.mitre.org/techniques/T1592/) |
| web3-audit | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1565](https://attack.mitre.org/techniques/T1565/) |
| webvuln | - | [T1190](https://attack.mitre.org/techniques/T1190/) [T1189](https://attack.mitre.org/techniques/T1189/) |
| wireless-pentester | infrastructure | [T1557](https://attack.mitre.org/techniques/T1557/) [T1040](https://attack.mitre.org/techniques/T1040/) |

Unmapped (process-only): bb-local-toolkit, bugcrowd-reporting, detection-engineer, evidence-hygiene, fix-verifier, hunt-dispatch, mid-engagement-ir-detection, redteam-mindset, redteam-report-template, report-generator, report-writing, sast-report, triage-validation

*Auto-generated by `agentx.mitre_navigator`. Do not hand-edit.*
