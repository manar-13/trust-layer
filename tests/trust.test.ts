import { describe, it, expect } from "vitest";
import { createAgent } from "../src/trust/identity";
import { issueCredential, verifySignature, isCredentialValid } from "../src/trust/credentials";
import { registerAgent, grantCredential, revokeCredential, findValidCredential, getTrustProfile } from "../src/trust/trustStore";
import { decideTask } from "../src/policy/decide";
import { requestPaymentAuthorization } from "../src/domains/paymentAuthorization";
import { requestDeploymentAuthorization } from "../src/domains/deploymentAuthorization";
import { requestDataAccessAuthorization } from "../src/domains/dataAccessAuthorization";

describe("identity and credentials", () => {
    it("creates an agent with a real key pair", () => {
        const { identity, privateKey } = createAgent("agent-a");
        expect(identity.publicKey).toContain("PUBLIC KEY");
        expect(privateKey).toContain("PRIVATE KEY");
    });

    it("issues a credential with a valid signature", () => {
        const { identity, privateKey } = createAgent("issuer-1");
        const credential = issueCredential(identity.id, privateKey, "subject-1", "can approve refunds", "payment:approve");
        expect(verifySignature(credential, identity.publicKey)).toBe(true);
    });

    it("rejects a tampered credential", () => {
        const { identity, privateKey } = createAgent("issuer-2");
        const credential = issueCredential(identity.id, privateKey, "subject-2", "can approve refunds", "payment:approve");
        const tampered = { ...credential, statement: "can approve unlimited refunds" };
        expect(verifySignature(tampered, identity.publicKey)).toBe(false);
    });

    it("rejects a credential signed by the wrong key", () => {
        const { identity: realIssuer, privateKey: realKey } = createAgent("issuer-3");
        const { identity: fakeIssuer } = createAgent("issuer-fake");
        const credential = issueCredential(realIssuer.id, realKey, "subject-3", "can deploy", "deploy:production");
        expect(verifySignature(credential, fakeIssuer.publicKey)).toBe(false);
    });

    it("flags an expired credential as invalid", () => {
        const { identity, privateKey } = createAgent("issuer-4");
        const credential = issueCredential(identity.id, privateKey, "subject-4", "can access data", "data:access", -1);
        const result = isCredentialValid(credential, identity.publicKey);
        expect(result.valid).toBe(false);
        expect(result.reason).toContain("expired");
    });
});

describe("trust store", () => {
    it("grants and finds a valid credential", () => {
        const { identity, privateKey } = createAgent("issuer-5");
        registerAgent(identity);
        grantCredential(identity.id, privateKey, "subject-5", "can approve payments", "payment:approve");
        const found = findValidCredential("subject-5", "payment:approve");
        expect(found).toBeDefined();
    });

    it("revoked credentials are no longer found as valid", () => {
        const { identity, privateKey } = createAgent("issuer-6");
        registerAgent(identity);
        const credential = grantCredential(identity.id, privateKey, "subject-6", "can deploy", "deploy:production");
        revokeCredential(credential.id, "agent behaved suspiciously");
        const found = findValidCredential("subject-6", "deploy:production");
        expect(found).toBeUndefined();
    });

    it("trust profile keeps revoked credentials visible for transparency", () => {
        const { identity, privateKey } = createAgent("issuer-7");
        registerAgent(identity);
        const credential = grantCredential(identity.id, privateKey, "subject-7", "can access data", "data:access");
        revokeCredential(credential.id, "no longer needed");
        const profile = getTrustProfile("subject-7");
        expect(profile.credentials.find(c => c.id === credential.id)?.status).toBe("revoked");
    });
});

describe("policy decisions", () => {
    it("accepts a task when a valid credential exists", () => {
        const { identity, privateKey } = createAgent("issuer-8");
        registerAgent(identity);
        grantCredential(identity.id, privateKey, "subject-8", "can approve payments", "payment:approve");
        const decision = decideTask({ requesterId: "subject-8", scope: "payment:approve", description: "approve $50" });
        expect(decision.outcome).toBe("accept");
    });

    it("refuses a task when no credential exists", () => {
        const decision = decideTask({ requesterId: "nobody", scope: "payment:approve", description: "approve $50" });
        expect(decision.outcome).toBe("refuse");
    });
});

describe("domains", () => {
    it("wires payment authorization correctly", () => {
        const { identity, privateKey } = createAgent("issuer-9");
        registerAgent(identity);
        grantCredential(identity.id, privateKey, "payer-1", "can approve payments up to $500", "payment:approve");
        const decision = requestPaymentAuthorization({ requesterId: "payer-1", amount: 200 });
        expect(decision.outcome).toBe("accept");
    });

    it("wires deployment authorization correctly", () => {
        const decision = requestDeploymentAuthorization({ requesterId: "unknown-deployer", environment: "production" });
        expect(decision.outcome).toBe("refuse");
    });

    it("wires data access authorization correctly", () => {
        const { identity, privateKey } = createAgent("issuer-10");
        registerAgent(identity);
        grantCredential(identity.id, privateKey, "reader-1", "can read analytics data", "data:access");
        const decision = requestDataAccessAuthorization({ requesterId: "reader-1", dataset: "analytics" });
        expect(decision.outcome).toBe("accept");
    });
});