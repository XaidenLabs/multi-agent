const encoder = new TextEncoder();

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export interface PrfOutputProvider {
  evaluate(salt: Uint8Array): Promise<Uint8Array>;
}

export interface EncryptedEvidenceEnvelope {
  schemaVersion: "dadieng.mera-evidence.v1";
  namespace: string;
  iv: string;
  ciphertext: string;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function namespaceSalt(namespace: string): Promise<Uint8Array> {
  if (!/^dadieng\/(evidence|validator|export)\/[a-zA-Z0-9._/-]{3,180}$/.test(namespace)) {
    throw new Error("Invalid Dadieng Mera key namespace");
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(namespace)));
}

export function createWebAuthnPrfProvider(credentialId: Uint8Array): PrfOutputProvider {
  return {
    async evaluate(salt) {
      if (!globalThis.navigator?.credentials) throw new Error("WebAuthn is unavailable");
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          allowCredentials: [{ id: arrayBuffer(credentialId), type: "public-key" }],
          userVerification: "required",
          extensions: { prf: { eval: { first: arrayBuffer(salt) } } } as AuthenticationExtensionsClientInputs,
        },
      }) as PublicKeyCredential | null;
      const extension = credential?.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & { prf?: { results?: { first?: ArrayBuffer } } };
      const output = extension.prf?.results?.first;
      if (!output) throw new Error("Authenticator did not return a Mera-compatible PRF output");
      return new Uint8Array(output);
    },
  };
}

export async function deriveMeraEvidenceKey(provider: PrfOutputProvider, namespace: string): Promise<CryptoKey> {
  const salt = await namespaceSalt(namespace);
  const prfOutput = await provider.evaluate(salt);
  if (prfOutput.byteLength < 32) throw new Error("Mera PRF output must contain at least 256 bits");
  const material = await crypto.subtle.importKey("raw", arrayBuffer(prfOutput), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: arrayBuffer(salt), info: encoder.encode("dadieng-evidence-aes-gcm-v1") },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptEvidenceWithMera(
  provider: PrfOutputProvider,
  namespace: string,
  plaintext: Uint8Array,
  iv = crypto.getRandomValues(new Uint8Array(12)),
): Promise<EncryptedEvidenceEnvelope> {
  const key = await deriveMeraEvidenceKey(provider, namespace);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: arrayBuffer(iv), additionalData: encoder.encode(namespace) }, key, arrayBuffer(plaintext));
  return { schemaVersion: "dadieng.mera-evidence.v1", namespace, iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

export async function decryptEvidenceWithMera(provider: PrfOutputProvider, envelope: EncryptedEvidenceEnvelope): Promise<Uint8Array> {
  const key = await deriveMeraEvidenceKey(provider, envelope.namespace);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: arrayBuffer(base64ToBytes(envelope.iv)), additionalData: encoder.encode(envelope.namespace) },
    key,
    arrayBuffer(base64ToBytes(envelope.ciphertext)),
  );
  return new Uint8Array(plaintext);
}
