import { hashMessage, recoverMessageAddress } from "viem";

export interface DynamicWallet {
  address: `0x${string}`;
  signMessage(message: string): Promise<`0x${string}`>;
}

export interface ParticipantAction {
  action: "publish-defense" | "register-validator" | "quarantine-version" | "claim-reward";
  resourceId: string;
  payloadHash: `0x${string}`;
  chainId: number;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
}

export function participantSigningMessage(address: `0x${string}`, input: ParticipantAction): string {
  if (Date.parse(input.expiresAt) <= Date.parse(input.issuedAt)) throw new Error("Participant action expiry must follow issue time");
  return [
    "Dadieng participant authorization v1",
    `actor: ${address.toLowerCase()}`,
    `action: ${input.action}`,
    `resource: ${input.resourceId}`,
    `payload: ${input.payloadHash}`,
    `chain: ${input.chainId}`,
    `issued-at: ${input.issuedAt}`,
    `expires-at: ${input.expiresAt}`,
    `nonce: ${input.nonce}`,
  ].join("\n");
}

export async function signParticipantAction(wallet: DynamicWallet, input: ParticipantAction) {
  const message = participantSigningMessage(wallet.address, input);
  const signature = await wallet.signMessage(message);
  const recoveredAddress = await recoverMessageAddress({ message, signature });
  if (recoveredAddress.toLowerCase() !== wallet.address.toLowerCase()) throw new Error("Dynamic wallet signature did not recover to the participant");
  return { address: wallet.address, messageHash: hashMessage(message), signature, input };
}
