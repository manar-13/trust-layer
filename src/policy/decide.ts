import { TaskRequest, TrustDecision } from "../trust/types";
import { findValidCredential } from "../trust/trustStore";

export function decideTask(task: TaskRequest): TrustDecision {
    const credential = findValidCredential(task.requesterId, task.scope);

    if (credential) {
        return {
            outcome: "accept",
            reason: `${task.requesterId} has a valid credential for "${task.scope}": "${credential.statement}" (issued by ${credential.issuerId}, verified).`,
            checkedCredentialId: credential.id,
        };
    }

    return {
        outcome: "refuse",
        reason: `${task.requesterId} has no valid credential for "${task.scope}". Refusing: ${task.description}`,
    };
}