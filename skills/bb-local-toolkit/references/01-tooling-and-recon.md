# TOOLS

## Go Binaries
| Tool | Use |
|------|-----|
| subfinder | Passive subdomain enum |
| httpx | Probe live hosts |
| dnsx | DNS resolution |
| nuclei | Template scanner |
| katana | Crawl |
| waybackurls | Archive URLs |
| gau | Known URLs |
| dalfox | XSS scanner |
| ffuf | Fuzzer |
| anew | Dedup append |
| qsreplace | Replace param values |
| assetfinder | Subdomain enum |
| gf | Grep patterns (xss, sqli, ssrf, redirect) |
| interactsh-client | OOB callbacks |

## Tools to Install When Needed
| Tool | Use | Install |
|------|-----|---------|
| arjun | Hidden parameter discovery | `pip3 install arjun` |
| paramspider | URL parameter mining | `pip3 install paramspider` |
| kiterunner | API endpoint brute | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| cloudenum | Cloud asset enumeration | `pip3 install cloud_enum` |
| trufflehog | Secret scanning | `brew install trufflehog` |
| gitleaks | Secret scanning | `brew install gitleaks` |
| XSStrike | Advanced XSS scanner | `pip3 install xsstrike` |
| SecretFinder | JS secret extraction | `pip3 install secretfinder` |
| sqlmap | SQL injection | `pip3 install sqlmap` |
| subzy | Subdomain takeover | `go install github.com/LukaSikic/subzy@latest` |

## Static Analysis (Semgrep Quick Audit)
```bash
# Install: pip3 install semgrep

# Broad security audit
semgrep --config=p/security-audit ./
semgrep --config=p/owasp-top-ten ./

# Language-specific rulesets
semgrep --config=p/javascript ./src/
semgrep --config=p/python ./
semgrep --config=p/golang ./
semgrep --config=p/php ./
semgrep --config=p/nodejs ./

# Targeted rules
semgrep --config=p/sql-injection ./
semgrep --config=p/jwt ./

# Custom pattern (example: find SQL concat in Python)
semgrep --pattern 'cursor.execute("..." + $X)' --lang python .

# Output to file for analysis
semgrep --config=p/security-audit ./ --json -o semgrep-results.json 2>/dev/null
cat semgrep-results.json | jq '.results[] | select(.extra.severity == "ERROR") | {path:.path, check:.check_id, msg:.extra.message}'
```

## FFUF Advanced Techniques
```bash
# THE ONE RULE: Always use -ac (auto-calibrate filters noise automatically)
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac

# Authenticated raw request file — IDOR testing (save Burp request to req.txt, replace ID with FUZZ)
seq 1 10000 | ffuf --request req.txt -w - -ac

# Authenticated API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w wordlist.txt -H "Cookie: session=TOKEN" -ac

# Parameter discovery
ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://target.com/api/endpoint?FUZZ=test" -ac -mc 200

# Hidden POST parameters
ffuf -w ~/wordlists/burp-parameter-names.txt -X POST -d "FUZZ=test" -u "https://target.com/api/endpoint" -ac

# Subdomain scan
ffuf -w subs.txt -u https://FUZZ.target.com -ac

# Filter strategies:
# -fc 404,403          Filter status codes
# -fs 1234             Filter by response size
# -fw 50               Filter by word count
# -fr "not found"      Filter regex in response body
# -rate 5 -t 10        Rate limit + fewer threads for stealth
# -e .php,.bak,.old    Add extensions
# -o results.json      Save output
```

## AI-Assisted Tools
- **strix** (usestrix.com) -- open-source AI scanner for automated initial sweep

---

# PHASE 1: RECON

## Standard Recon Pipeline
```bash
# Step 1: Subdomains
subfinder -d TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only TARGET | anew /tmp/subs.txt

# Step 2: Resolve + live hosts
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect -o /tmp/live.txt

# Step 3: URL collection
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/urls.txt
echo TARGET | waybackurls | anew /tmp/urls.txt
gau TARGET | anew /tmp/urls.txt

# Step 4: Nuclei scan
nuclei -l /tmp/live.txt -severity critical,high,medium -silent -o /tmp/nuclei.txt

# Step 5: JS secrets
cat /tmp/urls.txt | grep "\.js$" | sort -u > /tmp/jsfiles.txt
# Run SecretFinder on each JS file

# Step 6: GitHub dorking (if target has public repos)
# GitDorker -org TARGET_ORG -d dorks/alldorksv3
```

## Cloud Asset Enumeration
```bash
# Manual S3 brute
for suffix in dev staging test backup api data assets static cdn; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://${TARGET}-${suffix}.s3.amazonaws.com/")
  [ "$code" != "404" ] && echo "$code ${TARGET}-${suffix}.s3.amazonaws.com"
done
```

## API Endpoint Discovery
```bash
# ffuf API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,403 -ac
```

## HackerOne Scope Retrieval
```bash
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"PROGRAM_HANDLE\") { name url policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty instruction } } } } }"}' \
  | jq '.data.team.policy_scopes.edges[].node'
```

## Quick Wins Checklist
- [ ] Subdomain takeover (`subjack`, `subzy`)
- [ ] Exposed `.git` (`/.git/config`)
- [ ] Exposed env files (`/.env`, `/.env.local`)
- [ ] Default credentials on admin panels
- [ ] JS secrets (SecretFinder, jsluice)
- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)
- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)
- [ ] S3/cloud buckets
- [ ] GraphQL introspection enabled
- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`)
- [ ] Firebase open read (`https://TARGET.firebaseio.com/.json`)

## Technology Fingerprinting

| Signal | Technology |
|---|---|
| Cookie: `XSRF-TOKEN` + `*_session` | Laravel |
| Cookie: `PHPSESSID` | PHP |
| Header: `X-Powered-By: Express` | Node.js/Express |
| Response: `wp-json`/`wp-content` | WordPress |
| Response: `{"errors":[{"message":` | GraphQL |
| Header: `X-Powered-By: Next.js` | Next.js |

## Framework Quick Wins

**Laravel**: `/horizon`, `/telescope`, `/.env`, `/storage/logs/laravel.log`
**WordPress**: `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/?author=1`
**Node.js**: `/.env`, `/graphql` (introspection), `/_debug`
**AWS Cognito**: `/oauth2/userInfo` (leaks Pool ID), CORS reflects arbitrary origins

## Source Code Recon
```bash
# Security surface
cat SECURITY.md 2>/dev/null; cat CHANGELOG.md | head -100 | grep -i "security\|fix\|CVE"
git log --oneline --all --grep="security\|CVE\|fix\|vuln" | head -20

# Dev breadcrumbs
grep -rn "TODO\|FIXME\|HACK\|UNSAFE" --include="*.ts" --include="*.js" | grep -iv "test\|spec"

# Dangerous patterns (JS/TS)
grep -rn "eval(\|innerHTML\|dangerouslySetInner\|execSync" --include="*.ts" --include="*.js" | grep -v node_modules
grep -rn "===.*token\|===.*secret\|===.*hash" --include="*.ts" --include="*.js"
grep -rn "fetch(\|axios\." --include="*.ts" | grep "req\.\|params\.\|query\."

# Dangerous patterns (Solidity)
grep -rn "tx\.origin\|delegatecall\|selfdestruct\|block\.timestamp" --include="*.sol"
```

### Language-Specific Grep Patterns

```bash
# JavaScript/TypeScript -- prototype pollution, postMessage, RCE sinks
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" | grep -v node_modules
grep -rn "postMessage\|addEventListener.*message" --include="*.js" | grep -v node_modules
grep -rn "child_process\|execSync\|spawn(" --include="*.js" | grep -v node_modules

# Python -- pickle, yaml.load, eval, shell injection
grep -rn "pickle\.loads\|yaml\.load\|eval(" --include="*.py" | grep -v test
grep -rn "subprocess\|os\.system\|os\.popen" --include="*.py" | grep -v test
grep -rn "__import__\|exec(" --include="*.py"

# PHP -- type juggling, unserialize, LFI
grep -rn "unserialize\|eval(\|preg_replace.*e" --include="*.php"
grep -rn "==.*password\|==.*token\|==.*hash" --include="*.php"
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" | grep "include\|require\|file_get"

# Go -- template.HTML, race conditions
grep -rn "template\.HTML\|template\.JS\|template\.URL" --include="*.go"
grep -rn "go func\|sync\.Mutex\|atomic\." --include="*.go"

# Ruby -- YAML.load, mass assignment
grep -rn "YAML\.load[^_]\|Marshal\.load\|eval(" --include="*.rb"
grep -rn "attr_accessible\|permit(" --include="*.rb"

# Rust -- panic on network input, unsafe blocks
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "unsafe {" --include="*.rs" -B5 | grep "read\|recv\|parse\|decode"
grep -rn "as u8\|as u16\|as u32\|as usize" --include="*.rs" | grep -v "checked\|saturating\|wrapping"
```

---

