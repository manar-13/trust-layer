import { generateKeyPairSync } from "crypto";
import { AgentIdentity } from "./types";

export interface NewAgent {
    identity: AgentIdentity;   // safe to share — this is what other agents see
    privateKey: string;        // secret — only the agent itself should ever hold this
}

// Creates a brand-new agent with a real Ed25519 key pair.
export function createAgent(id: string): NewAgent {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const identity: AgentIdentity = {
        id,
        publicKey,
        createdAt: new Date().toISOString(),
    };

    return { identity, privateKey };
}