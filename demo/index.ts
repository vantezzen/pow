/**
 * This is a demo of how to use the @vantezzen/pow library.
 * In a real application, the client and server should run in their
 * own environment (e.g. client in the browser, server in Node.js).
 *
 * This demo uses the same environment for both client and server to
 * demonstrate how the library works in a simple way.
 */
import { PowClient, PowCrypto, PowServer } from "../src";

(async () => {
  // You can use any secret key you want or use `PowCrypto` to generate a random key instead
  const powCrypto = new PowCrypto();
  const secret = await powCrypto.generateSecret();
  console.log("Secret: " + secret);

  // Create a new client and server
  // In a real application, this would be done in different environments
  const powClient = new PowClient();
  const powServer = new PowServer(secret);

  // 1. Your server creates a challenge
  const challenge = await powServer.createChallenge();

  // 2. Your client solves the challenge using proof of work
  const nonce = await powClient.solveChallenge(challenge);
  console.log("Nonce: " + nonce);

  // 3. Your server verifies the challenge and nonce
  console.log("Testing valid proof of work");
  const result = await powServer.verifyProofOfWork(challenge, nonce);
  console.log(result);

  // This is an example of how an invalid nonce would perform
  console.log("Testing invalid proof of work");
  const result2 = await powServer.verifyProofOfWork(challenge, "123");
  console.log(result2);
})();
