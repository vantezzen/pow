import { PowCrypto } from "./PowCrypto";

/**
 * Configuration for the proof of work client
 * @param difficulty The difficulty of the proof of work. The higher the difficulty, the more work is required to find a valid nonce. The difficulty should be equal to the difficulty of the server.
 * @param timeout The timeout in milliseconds for the proof of work. If the proof of work is not found within the timeout, an error is thrown.
 */
export type PowClientConfig = {
  difficulty: number;
  timeout: number;
};

export const DEFAULT_POW_CLIENT_CONFIG: PowClientConfig = {
  difficulty: 4,
  timeout: 1000 * 10,
};

/**
 * The proof of work client.
 * This should be used client-side to perform the proof of work.
 */
export class PowClient {
  private crypto = new PowCrypto();

  constructor(private config: PowClientConfig = DEFAULT_POW_CLIENT_CONFIG) {}

  /**
   * Performs the proof of work. This function will loop until a valid nonce is found or the timeout is reached.
   *
   * @param challenge The challenge to solve
   * @returns The nonce that solves the challenge
   * @throws Error if the timeout is reached
   */
  public async solveChallenge(challenge: string): Promise<string> {
    let nonce = 0;
    let startTime = Date.now();

    while (true) {
      const hashValue = await this.crypto.hash(challenge + nonce);
      if (hashValue.startsWith("0".repeat(this.config.difficulty))) {
        return nonce.toString();
      }
      nonce++;

      if (Date.now() - startTime > this.config.timeout) {
        throw new Error("Timeout");
      }
    }
  }
}
