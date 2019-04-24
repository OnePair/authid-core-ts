import { AuthIDDriver } from "./authid-driver";

import Url from "url";
import Crypto from "crypto";
import CachMap from "caching-map";
import Jwt from "jsonwebtoken";

const DID_PROTOCOL = "DID:";

const DH_CURVE = "secp256k1"
const NONCE_LENGTH = 32;
const AUTH_EXPIRY = 10 * 60000; // 10 minutes

export class AuthID {
  private drivers: object;
  private didMethods: object;
  private challengeKey: any; // Diffie hellman key used for creating auth requests
  private authKey: Crypto.ECDH; // Diffie hellman key used for auth response
  private authChallenges: CachMap;

  constructor() {
    this.drivers = {}
    this.didMethods = {};
    this.authChallenges = new CachMap(Infinity);
  }

  public setDriver(protocol: string, didMethod: string, authIDDriver: AuthIDDriver): void {
    this.drivers[protocol.toUpperCase()] = authIDDriver;
    this.didMethods[didMethod.toUpperCase()] = protocol;
    this.challengeKey = AuthID.generateECDH();
    this.authKey = AuthID.generateECDH();
  }

  /*
  * Gets the crypto/ledger address.
  *
  * @param {string} protocol The registry protocol
  * @param {string} password The wallet password.
  *
  * @return {Promise<string>} The address.
  */
  public getAddress(protocol: string, password: string): Promise<string> {
    return this.getDriver(protocol).getAddress(password);
  }

  /*
  * Register a DID.
  *
  * @param {string} protocol The registry protocol.
  * @param {string} password The wallet password.
  *
  * @return {Promise<string>} The uri of the did.
  */
  public registerDID(protocol: string, password: string): Promise<string> {
    return this.getDriver(protocol).registerDID(password);
  }

  /*
  * Import a DID.
  *
  * @param {string} protocol The registry protocol.
  * @param {string} password The wallet password.
  * @param {string} did The did
  */
  public importDID(password: string, did: string): Promise<void> {
    let protocol = this.getProtocolFromId(did);
    return this.getDriver(protocol).importDID(password, did);
  }

  /*
  * Register a name.
  *
  * @param {string} protocol The driver protocol.
  * @param {string} password The wallet password.
  * @param {string} name The name to register.
  *
  * @return {Promise<string>} The transaction address.
  */
  public registerName(protocol: string,
    password: string, name: string): Promise<string> {
    return this.getDriver(protocol).registerName(password, name);
  }

  /*
  * Import an already registered name.
  *
  * @param {string} password The wallet password.
  * @param {string} name The name to import.
  */
  public importName(name: string): Promise<void> {
    let protocol = this.getProtocolFromId(name);
    return this.getDriver(protocol).importName(name);
  }

  /*
  * Authorize a processor.
  *
  * @param {string} protocol The registry protocol.
  * @param {string} password The wallet password.
  * @param {string} processorId String used to identify the processor.
  * @param {string} publicKey The public key of the processor.
  * @param {boolean} sig Permission for authentication.
  * @param {boolean} auth Permission for authentication.
  *
  * @param {string} The processor token.
  */

  public authorizeProcessor(protocol: string, password: string, processorId: string,
    publicKey: string, sig: boolean, auth: boolean): Promise<string> {
    return this.getDriver(protocol).authorizeProcessor(password, processorId, publicKey, sig, auth);
  }

  /*
  * Import a processor.
  *
  * @param {string} protocol The registry protocol.
  * @param {string} password The wallet password.
  * @param {string} processorId String used to indentify the processor.
  * @param {string} processorToken The processor token.
  * @param {string} privateKey The private key of the processor.
  */
  public importProcessor(protocol: string, password: string, processorId: string,
    processorToken: string, privateKey: string): Promise<void> {
    return this.getDriver(protocol).importProcessor(password, processorId, processorToken, privateKey);
  }

  /*toLowerCase
  * Revoke a processor.
  *
  * @param {string} protocol The registry protocol.
  * @param {string} password The wallet password.
  * @param {string} processorId The string used to identify the processor.
  */
  public revokeProcessor(protocol: string, password: string, processorId: string): Promise<void> {
    return this.getDriver(protocol).revokeProcessor(password, processorId);
  }

  /*
  * Create a new JWT.
  *
  * @param {string} protocol The registry protocol
  * @param {string} password The wallet password.
  * @param {object} claims The claims for the jwt.
  * @param {string} expiresIn Expiry time.
  * @param [string] permission
  *
  * @return {Promise<string>} The jwt.
  */
  public createJwt(protocol: string, password: string, claims: object,
    expiresIn: string): Promise<string>;
  public createJwt(protocol: string, password: string, claims: object,
    expiresIn: string, permission: string): Promise<string>;
  public createJwt(protocol: string, password: string, claims: object,
    expiresIn: string, permission?: string): Promise<string> {
    return this.getDriver(protocol).createJwt(password, claims,
      expiresIn, permission);
  }

  /*
  * Verify a jwt.
  *
  * @param {string} jwt The json web token.
  * @param {string} id The id that signed the jwt.
  * @param [string] permission
  *
  * @return {Promis<object>} The verification result.
  */
  public verifyJwt(jwt: string, id: string): Promise<object>;
  public verifyJwt(jwt: string, id: string,
    permission: string): Promise<object>;
  public verifyJwt(jwt: string, id: string,
    permission?: string): Promise<object> {
    let protocol = this.getProtocolFromId(id);
    return this.getDriver(protocol).verifyJwt(jwt, id, permission);
  }

  /*
  * Create an authentication request.
  *
  * @param {string} id The identifier to be challenged.
  *
  * @return {Promise<object>} The challenge.
  */
  public createAuthRequest(id: string): object {
    let nonce = Crypto.randomBytes(NONCE_LENGTH).toString("hex");
    this.authChallenges.set(id, nonce, { AUTH_EXPIRY });
    let challengePublicKey = this.challengeKey.getPublicKey("hex");

    let challenge = {
      receiver: id,
      nonce: nonce,
      challengePublicKey: challengePublicKey
    }

    return challenge;
  }

  /*
  * Sign authentication request.
  *
  * @param {string} password The wallet password.
  * @param {object} authRequest The authentication request.
  *
  * @return {Promise<string>} The response.
  */
  public signAuthRequest(password: string,
    authRequest: object): Promise<string> {
    return new Promise<string>(async (onSuccess: Function, onError: Function) => {
      try {
        // 1) Generate the shared secret
        let challengePublicKey =
          Buffer.from(authRequest["challengePublicKey"], "hex");
        let sharedSecret =
          this.authKey.computeSecret(challengePublicKey).toString("hex");

        console.log("Shared secret:", sharedSecret);
        // 2) Append the nonce to the shared secret
        let challenge = sharedSecret + authRequest["nonce"];

        // 3) Hash the challenge
        let hashedChallenge = Crypto.createHash("sha256")
          .update(challenge)
          .digest("hex");

        console.log("Created challenge:", hashedChallenge);

        // 4) Assemble the response object
        let publicKey = this.authKey.getPublicKey().toString("hex");

        let response = {
          challenge: hashedChallenge,
          signer: authRequest["receiver"],
          publicKey: publicKey
        };

        // 5) sign the response object
        let protocol = this.getProtocolFromId(authRequest["receiver"]);

        let signedResponse =
          await this.createJwt(protocol, password, response, null);

        onSuccess(signedResponse);
      } catch (err) {
        onError(err);
      }
    });
  }

  /*
  * Verify an authentication response.
  *
  * @param {string} AuthResponse The auth response.
  * @param {string} id The identifier.
  *
  * @return {Promise<object>} The verification result.
  */
  public verifyAuthResponse(authResponse: string): Promise<object> {
    return new Promise<object>(async (onSuccess: Function, onError: Function) => {
      try {
        let decodedAuthResponse = Jwt.decode(authResponse);

        let signer = decodedAuthResponse["signer"];
        let authPublicKey = Buffer.from(decodedAuthResponse["publicKey"], "hex");
        let signedChallenge = decodedAuthResponse["challenge"];

        if (!this.authChallenges.has(signer))
          throw new Error("Auth request does not exist.");

        // 1) Verify the JWT
        await this.verifyJwt(authResponse, signer, "auth");

        // 2) Get the nonce
        let nonce = this.authChallenges.get(signer);
        this.authChallenges.delete(signer) // Remove the challenge

        // 3) Generate the shared secret
        let sharedSecret =
          this.challengeKey.computeSecret(authPublicKey).toString("hex");

        // 4) Append the nonce to the shared secret
        let challenge = sharedSecret + nonce;

        // 5) Hash the challenge
        let hashedChallenge = Crypto.createHash("sha256")
          .update(challenge)
          .digest("hex");

        let verified = hashedChallenge == signedChallenge;

        if (!verified)
          throw new Error("Failed to authenticate!");

        onSuccess({verified: verified, id: signer});

      } catch (err) {
        onError(err);
      }
    });
  }

  /*
  * Get some general info.
  *
  * @param {string} protocol The registry protocol
  * @return {Promise<object>}
  */
  public getInfo(protocol: string): Promise<object> {
    return this.getDriver(protocol).getInfo();
  }

  /*
  * Get the wallet's public keys.
  *
  * @param {string} password The wallet password.
  *
  * @return {Promise<object>} The keys.
  */
  public getPublicKeys(protocol: string, password: string): Promise<object> {
    return this.getDriver(protocol).getPublicKeys(password);
  }

  public getProtocolFromId(id: string): string {
    let parsed = Url.parse(id)

    if (parsed.protocol != null && parsed.protocol.toUpperCase() == DID_PROTOCOL) {
      let host = parsed.host.toUpperCase();

      if (!(host in this.didMethods))
        throw new Error("DID method not found!");
      return this.didMethods[parsed.host.toUpperCase()];
    }

    if (id.indexOf(".") > -1) {
      let protocol = id.substring(id.lastIndexOf(".") + 1).toUpperCase();;
      if (!(protocol in this.drivers))
        throw new Error("Unsupported protocol!");
      return protocol;
    }

    throw new Error("Invalid ID!");
  }

  private getDriver(protocol: string): AuthIDDriver {
    return this.drivers[protocol.toUpperCase()];
  }

  private static generateECDH(): any {
    let ecdh = Crypto.createECDH(DH_CURVE);
    ecdh.generateKeys();

    return ecdh;
  }
}
