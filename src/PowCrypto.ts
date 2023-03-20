import { toHexString } from "./shared";
import type { Crypto } from "@peculiar/webcrypto";

/**
 * Class that provides cryptographic functions for POW
 */
export class PowCrypto {
  private key: CryptoKey | null = null;
  private crypto: Crypto | null = null;

  /**
   * Creates a new instance of the POW crypto class
   *
   * @param secret The secret to use for the POW crypto. If no secret is provided, the encryption functions will not work but hashing and secret generation do.
   */
  constructor(private secret?: string) {}

  private async prepareCrypto(): Promise<void> {
    if (this.crypto) return;

    if (typeof window !== "undefined") {
      this.crypto = window.crypto;
    } else {
      this.crypto = await import("@peculiar/webcrypto").then(
        (m) => new m.Crypto()
      );
    }
  }

  private async prepareKey(): Promise<void> {
    await this.prepareCrypto();
    if (this.key) {
      return;
    }

    if (!this.secret) {
      throw new Error("No secret provided");
    }

    const enc = new TextEncoder();
    const keyMaterial = await this.crypto!.subtle.digest(
      "SHA-256",
      enc.encode(this.secret)
    );

    this.key = await this.crypto!.subtle.importKey(
      "raw",
      keyMaterial,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Encrypt a value using AES-GCM
   */
  public async encryptValue(value: string): Promise<string> {
    await this.prepareKey();
    const iv = this.crypto!.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const encodedValue = enc.encode(value);
    const encrypted = await this.crypto!.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      this.key!,
      encodedValue
    );
    const encryptedArray = Array.from(new Uint8Array(encrypted));
    const encryptedHex = toHexString(encryptedArray);
    const ivHex = toHexString(Array.from(iv));
    return ivHex + encryptedHex;
  }

  /**
   * Decrypt a value using AES-GCM
   */
  public async decryptValue(value: string): Promise<string> {
    await this.prepareKey();
    const iv = new Uint8Array(
      value
        .substring(0, 24)
        .match(/.{1,2}/g)!
        .map((byte) => parseInt(byte, 16))
    );
    const encrypted = new Uint8Array(
      value
        .substring(24)
        .match(/.{1,2}/g)!
        .map((byte) => parseInt(byte, 16))
    );
    const decrypted = await this.crypto!.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
      },
      this.key!,
      encrypted
    );
    const dec = new TextDecoder();
    return dec.decode(decrypted);
  }

  /**
   * Generate a new secret for AES-GCM
   */
  public async generateSecret(): Promise<string> {
    await this.prepareCrypto();
    const key = await this.crypto!.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    );

    const exportedKey = await this.crypto!.subtle.exportKey("raw", key);
    const exportedKeyArray = Array.from(new Uint8Array(exportedKey));
    return toHexString(exportedKeyArray);
  }

  /**
   * Hash a value using SHA-256
   */
  public async hash(value: string): Promise<string> {
    await this.prepareCrypto();
    const utf8 = new TextEncoder().encode(value);
    const hashBuffer = await this.crypto!.subtle.digest("SHA-256", utf8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((bytes) => bytes.toString(16).padStart(2, "0"))
      .join("");
    return hashHex;
  }
}
