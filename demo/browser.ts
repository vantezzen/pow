/**
 * Demo browser script for @vantezzen/pow.
 * Look at demo/index.ts for a more detailed example.
 */
import { PowClient, PowCrypto, PowServer } from "../src";

const output = document.getElementById("out");
const log = (msg: string) => {
  output!.innerHTML += "\n\n" + msg;
};

const runDemo = async () => {
  log("Generating secret key...");
  const powCrypto = new PowCrypto();
  const secret = await powCrypto.generateSecret();
  log("Secret: " + secret);

  const powClient = new PowClient();
  const powServer = new PowServer(secret);

  log("Creating challenge...");
  const challenge = await powServer.createChallenge();
  log("Challenge: " + challenge);

  log("Solving challenge...");
  const nonce = await powClient.solveChallenge(challenge);
  log("Nonce: " + nonce);

  log("Testing valid proof of work...");
  const result = await powServer.verifyProofOfWork(challenge, nonce);
  log(JSON.stringify(result));

  // This is an example of how an invalid nonce would perform
  log("Testing invalid proof of work...");
  const result2 = await powServer.verifyProofOfWork(challenge, "123");
  log(JSON.stringify(result2));
};
runDemo();
