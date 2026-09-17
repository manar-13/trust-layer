# Deliberate Failure Test

## The attack: spoof a credential by tampering with its statement

I tried to break my own system by taking a real, validly-signed credential and quietly changing what it says — the same way an attacker would try to escalate an agent's permissions without actually getting a new credential issued.

### The setup

Using the live demo's "Attack Simulation" (also available at `POST /api/attack/spoof`):

1. Take `trusted-agent`'s real, currently-active credential for `payment:approve` — the one that says "authorized to approve payments up to $500"
2. Make a copy of it, but change the `statement` field to say "authorized to approve payments up to $500 (TAMPERED: unlimited authority)" — leaving the signature untouched
3. Run `verifySignature()` on the tampered copy, using the issuer's real public key

```bash
curl -s -X POST https://trust-layer-uxlw.onrender.com/api/attack/spoof \
  -H "Content-Type: application/json" \
  -d '{"agentId":"trusted-agent","scope":"payment:approve"}'
```

### What actually happens

The signature check **fails**. Because the signature was computed over the exact original statement text, changing even one character breaks the mathematical match against the issuer's public key. The tampered credential is rejected, and `decideTask()` would refuse any task that tried to use it.

This is the result I wanted — but it's worth being honest about what this test does and doesn't prove.

### What this test actually proves, and what it doesn't

It proves that **tampering with an already-issued credential is caught**. It does not test a different, more realistic attack: what happens if an attacker steals an agent's *private key* outright. If that happened, the attacker could sign brand-new, perfectly valid credentials as that agent — and my system would have no way to tell the difference, because the signature would be mathematically correct. This system has no key-rotation or compromise-detection mechanism. If a private key leaks, every credential it ever signs is trusted forever, with no way to say "actually, ignore everything signed after this date."

### Why this happens

The trust model here answers "was this claim signed by the key it claims to be signed by?" — not "is this key still safe to trust?" Those are two different questions, and I only built the first one.

### What I'd do about it

A real fix needs key-compromise handling: a way for an agent (or a trusted authority) to say "this key is burned, distrust everything signed by it after time T," separate from revoking individual credentials one at a time. I'd also want short-lived credentials by default, so a stolen key has a smaller window to do damage before its signed claims expire naturally.

I'm including this honestly because it's the actual boundary of what my system protects against — not a strawman weakness I already fixed. A trust system should be judged on what it still can't catch, not just on the attack it was built to demonstrate.