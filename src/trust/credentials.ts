import { sign, verify, randomUUID } from "crypto";
import { Credential } from "./types";

// Builds the exact string that gets signed — every field that matters, joined together.
// Both signing and verifying must build this the same way, or the signature won't match.
function buildPayload(c: Pick<Credential, "id" | "issuerId" | "subjectId" | "statement" | "scope" | "issuedAt" | "expiresAt">): Buffer {
    const payload = [c.id, c.issuerId, c.subjectId, c.statement, c.scope, c.issuedAt, c.expiresAt].join("|");
    return Buffer.from(payload, "utf8");
}

// Issues a real, signed credential: "issuerId says subjectId can do X, until expiresAt."
export function issueCredential(
    issuerId: string,
    issuerPrivateKey: string,
    subjectId: string,
    statement: string,
    scope: string,
    validForDays: number = 365
): Credential {
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + validForDays * 24 * 60 * 60 * 1000).toISOString();
    const id = randomUUID();

    const payload = buildPayload({ id, issuerId, subjectId, statement, scope, issuedAt, expiresAt });
    const signature = sign(null, payload, issuerPrivateKey).toString("base64");

    return { id, issuerId, subjectId, statement, scope, issuedAt, expiresAt, signature, status: "active" };
}

// Checks the cryptographic signature only — does NOT check expiry or revocation.
export function verifySignature(credential: Credential, issuerPublicKey: string): boolean {
    try {
        const payload = buildPayload(credential);
        const signatureBuffer = Buffer.from(credential.signature, "base64");
        return verify(null, payload, issuerPublicKey, signatureBuffer);
    } catch {
        return false;
    }
}

// The full check: real signature, not expired, not revoked.
export function isCredentialValid(credential: Credential, issuerPublicKey: string): { valid: boolean; reason?: string } {
    if (!verifySignature(credential, issuerPublicKey)) {
        return { valid: false, reason: "signature does not match — this credential may be forged or tampered with" };
    }
    if (credential.status === "revoked") {
        return { valid: false, reason: `credential was revoked: ${credential.revokedReason ?? "no reason given"}` };
    }
    if (new Date(credential.expiresAt).getTime() < Date.now()) {
        return { valid: false, reason: "credential has expired" };
    }
    return { valid: true };
}