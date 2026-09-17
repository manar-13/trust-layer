import { decideTask } from "../policy/decide";
import { TrustDecision } from "../trust/types";

export interface DataAccessTaskInput {
    requesterId: string;
    dataset: string;
}

export function requestDataAccessAuthorization(input: DataAccessTaskInput): TrustDecision {
    return decideTask({
        requesterId: input.requesterId,
        scope: "data:access",
        description: `access dataset "${input.dataset}"`,
    });
}