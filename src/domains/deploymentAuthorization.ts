import { decideTask } from "../policy/decide";
import { TrustDecision } from "../trust/types";

export interface DeploymentTaskInput {
    requesterId: string;
    environment: string;   // e.g. "production" or "staging"
}

export function requestDeploymentAuthorization(input: DeploymentTaskInput): TrustDecision {
    return decideTask({
        requesterId: input.requesterId,
        scope: `deploy:${input.environment}`,
        description: `deploy to ${input.environment}`,
    });
}