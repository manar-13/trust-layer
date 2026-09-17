// The 4 things a credential's life can be in.
export type CredentialStatus = "active" | "revoked";

export interface AgentIdentity {
    id: string;
    publicKey: string;   // PEM-encoded public key — this is how others verify this agent's signatures
    createdAt: string;
}

// A signed claim: "issuer says subject is allowed to do X."
export interface Credential {
    id: string;
    issuerId: string;
    subjectId: string;
    statement: string;   // plain-English claim, e.g. "authorized to approve payments up to $500"
    scope: string;        // machine-checkable scope, e.g. "payment:approve"
    issuedAt: string;
    expiresAt: string;
    signature: string;    // the actual cryptographic signature over the claim above
    status: CredentialStatus;
    revokedReason?: string;
}

export interface TrustProfile {
    agentId: string;
    credentials: Credential[];   // every credential ever issued to this agent, active or not
}

export interface TaskRequest {
    requesterId: string;   // the agent asking to be trusted to do something
    scope: string;          // the specific permission required, e.g. "deploy:production"
    description: string;
}

export interface TrustDecision {
    outcome: "accept" | "refuse";
    reason: string;
    checkedCredentialId?: string;
}