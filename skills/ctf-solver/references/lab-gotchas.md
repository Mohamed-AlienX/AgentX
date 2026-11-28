# Lab gotchas for ctf-solver

## Scope and safety
- Confirm the challenge/lab target is explicitly authorized and in scope before running tools.
- Keep commands reproducible; capture exact command, target, timestamp, and output.
- Do not run destructive payloads outside isolated lab targets.

## Evidence discipline
- A claim is not a finding without reproducible evidence: command output, HTTP request/response pair, screenshot path, or shell proof.
- Save raw artifacts under the session output directory; summarize only in chat.
- Record negative results briefly so fallback decisions are auditable.

## Common lab pitfalls
- DNS/host mapping: add lab hostnames to hosts file only when authorized and documented.
- TLS/cert issues: verify whether the lab uses self-signed certs before disabling validation.
- Rate limits/WAF simulation: throttle scans; noisy tools can invalidate challenge state.
- Stateful services: reset/revert snapshots before re-testing exploit chains.
- Time skew: token/JWT/cookie expiry issues can mimic exploit failure.

## Fallback handoff
- On proof failure or blocked vector, record attempted vector/CVE, reason, service/port, duration, and next vector.
- Advance deterministically to next ranked vector; do not loop back into unbounded LLM retries.
