# Trust Layer

A trust profile system for AI agents, built on real cryptographic signatures instead of a made-up reputation score.

Live demo: https://trust-layer-uxlw.onrender.com
Repo: https://github.com/manar-13/trust-layer

## The problem

When one AI agent asks another agent to do something — approve a payment, deploy code, access private data — how does the second agent know the first one is actually allowed to ask for that? Most systems either trust everyone, or use a "reputation score" that's just a number with nothing backing it up.

## What this system does

Every agent gets a real Ed25519 key pair (the same kind of cryptography used to sign real transactions). When one agent wants to grant another agent permission to do something, it doesn't just say so — it **signs** that claim with its private key. Anyone can then verify that signature using the issuer's public key, without needing to trust the issuer's word for it.

This is called a **credential**: a signed claim that says "issuer X says agent Y is allowed to do Z." Before any agent is allowed to complete a task, the system checks:
1. Does the agent have a credential for this exact task?
2. Is the signature on that credential actually valid (not forged or tampered)?
3. Has it been revoked?
4. Has it expired?

Only if all four checks pass does the task get approved.

## The 3 domains

- **Payment authorization** — can this agent approve a payment?
- **Deployment authorization** — can this agent deploy to production?
- **Data access authorization** — can this agent access private data?

Each domain is a thin wrapper. None of them contain any trust logic themselves — they just describe what's being asked and hand it to one shared policy engine.

## Try it yourself

1. Open the live demo
2. Click "Set Up Demo Agents" — this creates a `trusted-agent` (who gets 3 real signed credentials) and a `stranger-agent` (who gets none)
3. Try requesting each of the 3 domains as both agents — watch trusted-agent get accepted and stranger-agent get refused
4. Try the "Attack Simulation" — it takes a real credential, tampers with it, and proves the signature check catches the forgery
5. Use the "Trust Profile Inspector" to see every credential ever issued to an agent, including revoked ones

## Tech stack

TypeScript, Node.js, Express, vitest for tests. No external crypto libraries — the signing and verification use Node's built-in `crypto` module (Ed25519).

## Project structure

src/
trust/ — identity creation, credential issuing/verification, the trust store
policy/ — the one shared decision engine every domain calls
domains/ — payment, deployment, data-access (thin wrappers)
server.ts — Express API
public/
index.html — the demo page
tests/
trust.test.ts — 13 tests covering identity, credentials, trust store, policy, and domains


See `ARCHITECTURE.md` for how the pieces connect, `FAILURE_TEST.md` for a deliberate attack I ran against my own system, and `THESIS.md` for where I think agent trust is headed.