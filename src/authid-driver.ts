export interface AuthIDDriver {

  /*
  * Gets the crypto/ledger address.
  *
  * @param {string} password The wallet password.
  *
  * @return {Promise<string>} The address.
  */
  getAddress(password: string): Promise<string>;

  /*
  * Register a DID.
  *
  * @param {string} password The wallet password.
  *
  * @return {Promise<string>} The uri of the did.
  */
  registerDID(password: string): Promise<string>;

  /*
  * Import a DID.
  *
  * @param {string} password The wallet password.
  * @param {string} password The wallet password.
  */
  importDID(password: string, did: string): Promise<void>;

  /*
  * Authorize a processor.
  *
  * @param {string} password The wallet password.
  * @param {string} processorId String used to identify the processor.
  * @param {string} publicKey The public key of the processor.
  * @param {boolean} sig Permission for authentication.
  * @param {boolean} auth Permission for authentication.
  *
  * @param {string} The processor token.
  */
  authorizeProcessor(password: string, processorId: string,
    publicKey: string, sig: boolean, auth: boolean): Promise<string>;

  /*
  * Import a processor.
  *
  * @param {string} password The wallet password.
  * @param {string} processorId String used to indentify the processor.
  * @param {string} processorToken The processor token.
  * @param {string} privateKey The private key of the processor.
  */
  importProcessor(password: string, processorId: string,
    processorToken: string, privateKey: string): Promise<void>;

  /*
  * Revoke a processor.
  *
  * @param {string} password The wallet password.
  * @param {string} processorId The string used to identify the processor.
  */
  revokeProcessor(password: string, processorId: string): Promise<void>;

  /*
  * Create a new JWT.
  *
  * @param {string} password The wallet password.
  * @param {object} claims The claims for the jwt.
  * @param {string} expiresIn Expiry time.
  *
  * @return {Promise<string>} The jwt.
  */
  createJwt(password: string, claims: object, expiresIn: string): Promise<string>;

  /*
  * Verify a jwt.
  *
  * @param {string} jwt The json web token.
  * @param {string} id The id that signed the jwt.
  *
  * @return {Promis<object>} The verification result.
  */
  verifyJwt(jwt: string, id: string): Promise<object>;

  /*
  * Get some general info.
  *
  * @return {Promise<object>}
  */
  getInfo(): Promise<object>;

  /*
  * Get the wallet's public keys.
  *
  * @return {Promise<object>} The keys.
  */
  getPublicKeys(): Promise<object>;

  /*
  * Initialize the driver
  */
  init(): Promise<void>;
}
