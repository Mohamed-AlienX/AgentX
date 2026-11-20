---
name: web3-audit
description: >-
  Smart contract security audit — 10 DeFi bug classes (accounting desync, access control,
  incomplete path, off-by-one, oracle, ERC4626, reentrancy, flash loan, signature replay,
  proxy), pre-dive kill signals (TVL < $500K etc), Foundry PoC template, grep patterns for
  each class, and real Immunefi paid examples. Use for any Solidity/Rust contract audit or
  when deciding whether a DeFi target is worth hunting. Do not use for token rug-pull or
  honeypot checks - use meme-coin-audit.
sources: public_research, community
mitre_attack: [T1190, T1565]
---

# WEB3 SMART CONTRACT AUDIT

10 bug classes. Pre-dive kill signals. Foundry PoC template. Real paid examples.

---

## PRE-DIVE KILL SIGNALS (check BEFORE any code review)

> ZKsync lesson: $322M TVL + OZ audit + 750K LOC + 5 sessions = 0 findings. Large well-audited bridges are extremely hard.

1. **TVL < $500K** → max payout capped too low for effort
2. **2+ top-tier audits** (Halborn, ToB, Cyfrin, OpenZeppelin) on simple protocol → bugs already found
3. **Protocol < 500 lines, single A→B→C flow** → minimal attack surface
4. **Formula**: `max_realistic_payout = min(10% × TVL, program_cap)` — if < $10K, skip

**Soft kill:** OZ/ToB/Cyfrin audit on current version + codebase > 500K LOC → expect 40+ hours for maybe 1 finding. Only proceed if bounty floor > $50K AND you have protocol-specific expertise.

**Target scoring (go if >= 6/10):**
- TVL > $10M: +2
- Immunefi program with Critical >= $50K: +2
- No top-tier audit on current version: +2
- < 30 days since deploy: +1
- Protocol you've hunted before: +1
- Source code + natspec comments: +1
- Upgradeable proxies: +1

---

## THE ONE RULE

> "Read ALL sibling functions. If `vote()` has a modifier, check `poke()`, `reset()`, `harvest()`. The missing modifier on the sibling IS the bug."

This single rule explains 19% of all Critical findings.

---

## 1. ACCOUNTING STATE DESYNCHRONIZATION
> #1 Critical bug class — 28% of all Criticals on Immunefi.

### What It Is
Two state variables supposed to stay in sync. One code path updates A but forgets B. Later code reads both and makes decisions based on stale B.

```
Real Value = A - B
If A updated but B isn't → Real Value appears larger → phantom value
```

### Root Cause Patterns

**Variant 1: Phantom Yield** (Yeet protocol — 35 duplicate reports)
```solidity
function startUnstake(uint256 amount) external {
    totalSupply -= amount;  // decremented BEFORE transfer
    // aToken.balanceOf(this) still reflects old value
    // yieldAmount = aToken.balanceOf - totalSupply = phantom yield
}
```

**Variant 2: Fast Path Skips State Update** (Alchemix V3)
```solidity
function claimRedemption(uint256 tokenId) external {
    if (transmuter.balance >= amount) {
        transmuter.transfer(user, amount);
        _burn(tokenId);
        return;  // EARLY RETURN — cumulativeEarmarked, _redemptionWeight, totalDebt never updated
    }
    // Slow path: updates all state vars correctly
    alchemist.redeem(...);
}
```

**Variant 3: Update Happens in Wrong Order** (Alchemix)
```solidity
function deposit(uint256 amount) external {
    _shares = (amount * totalShares) / totalAssets;  // calculated BEFORE deposit
    totalAssets += amount;   // assets added AFTER shares calculated → wrong rate
}
```

### Grep Patterns
```bash
# Find all accounting variables
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward\|rewardPerShare" contracts/

# Find all early returns in claim/redeem functions
grep -rn "\breturn\b" contracts/ -B3 | grep -B3 "if\b"

# For each early return: which state updates in normal path are skipped?
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-2-access-control.md` | 2. ACCESS CONTROL; 3. INCOMPLETE CODE PATH; 4. OFF-BY-ONE & BOUNDARY CONDITIONS; 5. ORACLE / PRICE MANIPULATION; 6. ERC4626 VAULT ATTACKS; 7. REENTRANCY; 8. FLASH LOAN ATTACKS |
| `references/02-9-signature-replay.md` | 9. SIGNATURE REPLAY; 10. PROXY / UPGRADE ISSUES; FOUNDRY POC TEMPLATE; Related Skills & Chains; Operator Notes (Claude-BugHunter) |
