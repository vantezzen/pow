import { PowCrypto } from "./PowCrypto";

/**
 * Configuration for the POW server
 *
 * @param difficulty The difficulty of the proof of work. The higher the difficulty, the more work is required to find a valid nonce. The difficulty should be equal to the difficulty of the client.
 * @param validity Validity of the challenge in milliseconds. This is the maximum time between the call to "generateChallenge" and the call to "verifyProofOfWork" to prevent replay attacks.
 */
export type PowServerConfig = {
  difficulty: number;
  validity: number;
};

export const DEFAULT_POW_SERVER_CONFIG: PowServerConfig = {
  difficulty: 4,
  validity: 1000 * 15, // 15 seconds
};

/**
 * Result of the proof of work verification
 */
export type PowVerifyResult = {
  isValid: boolean;
  error?: string;
};

/**
 * The proof of work server.
 * This should be used server-side to generate and verify the proof of work challenges.
 */
export class PowServer {
  private crypto: PowCrypto;

  /**
   * Creates a new proof of work server
   *
   * @param secret The secret used to encrypt and decrypt the challenge. This should be stored securely on the server.
   * @param config Optional configuration for the proof of work server
   */
  constructor(
    secret: string,
    private config: PowServerConfig = DEFAULT_POW_SERVER_CONFIG
  ) {
    this.crypto = new PowCrypto(secret);
  }

  /**
   * Verifies the proof of work challenge and nonce.
   */
  public async verifyProofOfWork(
    challenge: string,
    nonce: string
  ): Promise<PowVerifyResult> {
    const hashValue = await this.crypto.hash(challenge + nonce);
    const isValidNonce = hashValue.startsWith(
      "0".repeat(this.config.difficulty)
    );

    if (!isValidNonce) {
      return { isValid: false, error: "Invalid nonce" };
    }

    let decryptedPayload: string;
    try {
      decryptedPayload = await this.crypto.decryptValue(challenge);
    } catch (e) {
      return { isValid: false, error: "Invalid payload" };
    }

    const payloadTimestamp = parseInt(decryptedPayload);
    if (isNaN(payloadTimestamp)) {
      return { isValid: false, error: "Payload is not a valid timestamp" };
    }

    const now = Date.now();
    if (now - payloadTimestamp > this.config.validity) {
      return { isValid: false, error: "Payload is expired" };
    }

    if (now < payloadTimestamp) {
      return { isValid: false, error: "Payload is in the future" };
    }

    return { isValid: true };
  }

  /**
   * Generates a new challenge.
   */
  public async createChallenge(): Promise<string> {
    const payload = Date.now().toString();
    return this.crypto.encryptValue(payload);
  }
}
