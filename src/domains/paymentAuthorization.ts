import { decideTask } from "../policy/decide";
import { TrustDecision } from "../trust/types";

export interface PaymentTaskInput {
    requesterId: string;
    amount: number;
}

export function requestPaymentAuthorization(input: PaymentTaskInput): TrustDecision {
    return decideTask({
        requesterId: input.requesterId,
        scope: "payment:approve",
        description: `approve a payment of $${input.amount}`,
    });
}