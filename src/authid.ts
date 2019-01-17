import { AuthIDDriver } from "./authid-driver";

import Url from "url";

const DID_PROTOCOL = "DID:";

export class AuthID {
  private drivers: object;
  private didMethods: object;

  constructor() {
    this.drivers = {}
    this.didMethods = {};
  }

  public setDriver(protocol: string, didMethod: string, authIDDriver: AuthIDDriver): void {
    this.drivers[protocol.toUpperCase()] = authIDDriver;
    this.didMethods[didMethod.toUpperCase()] = protocol;
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
  registerDID(protocol: string, password: string): Promise<string> {
    return this.getDriver(protocol).registerDID(password);
  }

  /*
  * Import a DID.
  *
  * @param {string} protocol The registry protocol.
  * @param {string} password The wallet password.
  */
  importDID(protocol: string, did: string): Promise<void> {
    return this.getDriver(protocol).importDID(did);
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
  authorizeProcessor(protocol: string, password: string, processorId: string,
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
  importProcessor(protocol: string, password: string, processorId: string,
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
  revokeProcessor(protocol: string, password: string, processorId: string): Promise<void> {
    return this.getDriver(protocol).revokeProcessor(password, processorId);
  }

  /*
  * Create a new JWT.
  *
  * @param {string} protocol The registry protocol
  * @param {string} password The wallet password.
  * @param {object} claims The claims for the jwt.
  * @param {string} expiresIn Expiry time.
  *
  * @return {Promise<string>} The jwt.
  */
  createJwt(protocol: string, password: string, claims: object, expiresIn: string): Promise<string> {
    return this.getDriver(protocol).createJwt(password, claims, expiresIn);
  }

  /*
  * Verify a jwt.
  *
  * @param {string} jwt The json web token.
  * @param {string} id The id that signed the jwt.
  *
  * @return {Promis<object>} The verification result.
  */
  verifyJwt(jwt: string, id: string): Promise<object> {
    let protocol = this.getProtocolFromId(id);
    return this.getDriver(protocol).verifyJwt(jwt, id);
  }

  /*
  * Get some general info.
  *
  * @param {string} protocol The registry protocol
  * @return {Promise<object>}
  */
  getInfo(protocol: string): Promise<object> {
    return this.getDriver(protocol).getInfo();
  }

  public getProtocolFromId(id: string): string {
    let parsed = Url.parse(id)

    if (parsed.protocol != null && parsed.protocol.toUpperCase() == DID_PROTOCOL) {
      let host = parsed.host.toUpperCase();

      if (!(host in this.didMethods))
        throw new Error("DID method not found!");
      return this.didMethods[parsed.host.toUpperCase()];
    }

    throw new Error("Invalid ID!");
  }

  private getDriver(protocol: string): AuthIDDriver {
    return this.drivers[protocol.toUpperCase()];
  }
}
