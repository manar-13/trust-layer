import { AgentIdentity, Credential, TrustProfile } from "./types";
import { issueCredential, isCredentialValid } from "./credentials";

const agents = new Map<string, AgentIdentity>();
const credentials: Credential[] = [];

// --- IDENTITY ---
export function registerAgent(identity: AgentIdentity): void {
    agents.set(identity.id, identity);
}

export function getAgent(agentId: string): AgentIdentity | undefined {
    return agents.get(agentId);
}

// --- GRANTING TRUST (issuing a credential) ---
export function grantCredential(
    issuerId: string,
    issuerPrivateKey: string,
    subjectId: string,
    statement: string,
    scope: string,
    validForDays?: number
): Credential {
    const credential = issueCredential(issuerId, issuerPrivateKey, subjectId, statement, scope, validForDays);
    credentials.push(credential);
    return credential;
}

// --- REVOKING TRUST ---
export function revokeCredential(credentialId: string, reason: string): Credential | undefined {
    const credential = credentials.find(c => c.id === credentialId);
    if (credential) {
        credential.status = "revoked";
        credential.revokedReason = reason;
    }
    return credential;
}

// --- READING TRUST ---
// Everything ever issued to this agent, active or not — full history, nothing hidden.
export function getTrustProfile(agentId: string): TrustProfile {
    return {
        agentId,
        credentials: credentials.filter(c => c.subjectId === agentId),
    };
}

// Finds a genuinely valid credential (real signature, not expired, not revoked)
// for a given agent and scope. This is what the policy engine actually checks.
export function findValidCredential(subjectId: string, scope: string): Credential | undefined {
    return credentials.find(c => {
        if (c.subjectId !== subjectId || c.scope !== scope) return false;
        const issuer = agents.get(c.issuerId);
        if (!issuer) return false;
        return isCredentialValid(c, issuer.publicKey).valid;
    });
}