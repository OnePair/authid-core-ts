"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var url_1 = __importDefault(require("url"));
var DID_PROTOCOL = "DID:";
var AuthID = /** @class */ (function () {
    function AuthID() {
        this.drivers = {};
        this.didMethods = {};
    }
    AuthID.prototype.setDriver = function (protocol, didMethod, authIDDriver) {
        this.drivers[protocol.toUpperCase()] = authIDDriver;
        this.didMethods[didMethod.toUpperCase()] = protocol;
    };
    /*
    * Gets the crypto/ledger address.
    *
    * @param {string} protocol The registry protocol
    * @param {string} password The wallet password.
    *
    * @return {Promise<string>} The address.
    */
    AuthID.prototype.getAddress = function (protocol, password) {
        return this.getDriver(protocol).getAddress(password);
    };
    /*
    * Register a DID.
    *
    * @param {string} protocol The registry protocol.
    * @param {string} password The wallet password.
    *
    * @return {Promise<string>} The uri of the did.
    */
    AuthID.prototype.registerDID = function (protocol, password) {
        return this.getDriver(protocol).registerDID(password);
    };
    /*
    * Import a DID.
    *
    * @param {string} protocol The registry protocol.
    * @param {string} password The wallet password.
    * @param {string} did The did
    */
    AuthID.prototype.importDID = function (password, did) {
        var protocol = this.getProtocolFromId(did);
        return this.getDriver(protocol).importDID(password, did);
    };
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
    AuthID.prototype.authorizeProcessor = function (protocol, password, processorId, publicKey, sig, auth) {
        return this.getDriver(protocol).authorizeProcessor(password, processorId, publicKey, sig, auth);
    };
    /*
    * Import a processor.
    *
    * @param {string} protocol The registry protocol.
    * @param {string} password The wallet password.
    * @param {string} processorId String used to indentify the processor.
    * @param {string} processorToken The processor token.
    * @param {string} privateKey The private key of the processor.
    */
    AuthID.prototype.importProcessor = function (protocol, password, processorId, processorToken, privateKey) {
        return this.getDriver(protocol).importProcessor(password, processorId, processorToken, privateKey);
    };
    /*toLowerCase
    * Revoke a processor.
    *
    * @param {string} protocol The registry protocol.
    * @param {string} password The wallet password.
    * @param {string} processorId The string used to identify the processor.
    */
    AuthID.prototype.revokeProcessor = function (protocol, password, processorId) {
        return this.getDriver(protocol).revokeProcessor(password, processorId);
    };
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
    AuthID.prototype.createJwt = function (protocol, password, claims, expiresIn) {
        return this.getDriver(protocol).createJwt(password, claims, expiresIn);
    };
    /*
    * Verify a jwt.
    *
    * @param {string} jwt The json web token.
    * @param {string} id The id that signed the jwt.
    *
    * @return {Promis<object>} The verification result.
    */
    AuthID.prototype.verifyJwt = function (jwt, id) {
        var protocol = this.getProtocolFromId(id);
        return this.getDriver(protocol).verifyJwt(jwt, id);
    };
    /*
    * Get some general info.
    *
    * @param {string} protocol The registry protocol
    * @return {Promise<object>}
    */
    AuthID.prototype.getInfo = function (protocol) {
        return this.getDriver(protocol).getInfo();
    };
    /*
    * Get the wallet's public keys.
    *
    * @param {string} password The wallet password.
    *
    * @return {Promise<object>} The keys.
    */
    AuthID.prototype.getPublicKeys = function (protocol, password) {
        return this.getDriver(protocol).getPublicKeys(password);
    };
    AuthID.prototype.getProtocolFromId = function (id) {
        var parsed = url_1.default.parse(id);
        if (parsed.protocol != null && parsed.protocol.toUpperCase() == DID_PROTOCOL) {
            var host = parsed.host.toUpperCase();
            if (!(host in this.didMethods))
                throw new Error("DID method not found!");
            return this.didMethods[parsed.host.toUpperCase()];
        }
        throw new Error("Invalid ID!");
    };
    AuthID.prototype.getDriver = function (protocol) {
        return this.drivers[protocol.toUpperCase()];
    };
    return AuthID;
}());
exports.AuthID = AuthID;
