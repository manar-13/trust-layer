import express from "express";
import path from "path";
import { createAgent } from "./trust/identity";
import { registerAgent, grantCredential, revokeCredential, getTrustProfile, getAgent } from "./trust/trustStore";
import { requestPaymentAuthorization } from "./domains/paymentAuthorization";
import { requestDeploymentAuthorization } from "./domains/deploymentAuthorization";
import { requestDataAccessAuthorization } from "./domains/dataAccessAuthorization";
import { verifySignature } from "./trust/credentials";

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

// In-memory map of agentId -> privateKey, so the demo can sign credentials on an agent's behalf.
// In a real system each agent would hold its own private key — this is a demo-only shortcut.
const privateKeys = new Map<string, string>();

// --- Create a new agent (identity) ---
app.post("/api/agents", (req, res) => {
    const { id } = req.body;
    const { identity, privateKey } = createAgent(id);
    registerAgent(identity);
    privateKeys.set(id, privateKey);
    res.json(identity);
});

// --- Grant a credential (issuer -> subject) ---
app.post("/api/credentials/grant", (req, res) => {
    const { issuerId, subjectId, statement, scope, validForDays } = req.body;
    const issuerKey = privateKeys.get(issuerId);
    if (!issuerKey) {
        return res.status(400).json({ error: `Unknown issuer: ${issuerId}` });
    }
    const credential = grantCredential(issuerId, issuerKey, subjectId, statement, scope, validForDays);
    res.json(credential);
});

// --- Revoke a credential ---
app.post("/api/credentials/revoke", (req, res) => {
    const { credentialId, reason } = req.body;
    const credential = revokeCredential(credentialId, reason);
    res.json(credential ?? { error: "Not found" });
});

// --- Trust profile inspector ---
app.get("/api/trust/:agentId", (req, res) => {
    res.json(getTrustProfile(req.params.agentId));
});

// --- Trust-gated task requests (the 3 domains) ---
app.post("/api/tasks/payment", (req, res) => {
    res.json(requestPaymentAuthorization(req.body));
});
app.post("/api/tasks/deployment", (req, res) => {
    res.json(requestDeploymentAuthorization(req.body));
});
app.post("/api/tasks/data-access", (req, res) => {
    res.json(requestDataAccessAuthorization(req.body));
});

// --- Demo helper: tamper with a credential's statement to simulate a forged/spoofed claim ---
app.post("/api/attack/spoof", (req, res) => {
    const { agentId, scope } = req.body;
    const profile = getTrustProfile(agentId);
    const credential = profile.credentials.find(c => c.scope === scope && c.status === "active");
    if (!credential) {
        return res.status(400).json({ error: "No credential found to spoof" });
    }
    // Return what a tampered version of this credential would look like, and prove it fails verification.
    const tampered = { ...credential, statement: credential.statement + " (TAMPERED: unlimited authority)" };
    const issuer = getAgent(credential.issuerId);
    const stillValid = issuer ? verifySignature(tampered, issuer.publicKey) : false;
    res.json({ original: credential, tampered, signatureStillValid: stillValid });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`trust-layer is live on port ${PORT}`);
});