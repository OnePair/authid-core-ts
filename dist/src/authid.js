"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var url_1 = __importDefault(require("url"));
var crypto_1 = __importDefault(require("crypto"));
var caching_map_1 = __importDefault(require("caching-map"));
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var DID_PROTOCOL = "DID:";
var DH_CURVE = "secp256k1";
var NONCE_LENGTH = 32;
var AUTH_EXPIRY = 10 * 60000; // 10 minutes
var AuthID = /** @class */ (function () {
    function AuthID() {
        this.drivers = {};
        this.didMethods = {};
        this.authChallenges = new caching_map_1.default(Infinity);
    }
    AuthID.prototype.setDriver = function (protocol, didMethod, authIDDriver) {
        this.drivers[protocol.toUpperCase()] = authIDDriver;
        this.didMethods[didMethod.toUpperCase()] = protocol;
        this.challengeKey = AuthID.generateECDH();
        this.authKey = AuthID.generateECDH();
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
    * Register a name.
    *
    * @param {string} protocol The driver protocol.
    * @param {string} password The wallet password.
    * @param {string} name The name to register.
    *
    * @return {Promise<string>} The transaction address.
    */
    AuthID.prototype.registerName = function (protocol, password, name) {
        return this.getDriver(protocol).registerName(password, name);
    };
    /*
    * Import an already registered name.
    *
    * @param {string} password The wallet password.
    * @param {string} name The name to import.
    */
    AuthID.prototype.importName = function (name) {
        var protocol = this.getProtocolFromId(name);
        return this.getDriver(protocol).importName(name);
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
    AuthID.prototype.createJwt = function (protocol, password, claims, expiresIn, permission) {
        return this.getDriver(protocol).createJwt(password, claims, expiresIn, permission);
    };
    AuthID.prototype.verifyJwt = function (jwt, id, permission) {
        var protocol = this.getProtocolFromId(id);
        return this.getDriver(protocol).verifyJwt(jwt, id, permission);
    };
    /*
    * Create an authentication request.
    *
    * @param {string} id The identifier to be challenged.
    *
    * @return {Promise<object>} The challenge.
    */
    AuthID.prototype.createAuthRequest = function (id) {
        var nonce = crypto_1.default.randomBytes(NONCE_LENGTH).toString("hex");
        this.authChallenges.set(id, nonce, { AUTH_EXPIRY: AUTH_EXPIRY });
        var challengePublicKey = this.challengeKey.getPublicKey("hex");
        var challenge = {
            receiver: id,
            nonce: nonce,
            challengePublicKey: challengePublicKey
        };
        return challenge;
    };
    /*
    * Sign authentication request.
    *
    * @param {string} password The wallet password.
    * @param {object} authRequest The authentication request.
    *
    * @return {Promise<string>} The response.
    */
    AuthID.prototype.signAuthRequest = function (password, authRequest) {
        var _this = this;
        return new Promise(function (onSuccess, onError) { return __awaiter(_this, void 0, void 0, function () {
            var challengePublicKey, sharedSecret, challenge, hashedChallenge, publicKey, response, protocol, signedResponse, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        challengePublicKey = Buffer.from(authRequest["challengePublicKey"], "hex");
                        sharedSecret = this.authKey.computeSecret(challengePublicKey).toString("hex");
                        console.log("Shared secret:", sharedSecret);
                        challenge = sharedSecret + authRequest["nonce"];
                        hashedChallenge = crypto_1.default.createHash("sha256")
                            .update(challenge)
                            .digest("hex");
                        console.log("Created challenge:", hashedChallenge);
                        publicKey = this.authKey.getPublicKey().toString("hex");
                        response = {
                            challenge: hashedChallenge,
                            signer: authRequest["receiver"],
                            publicKey: publicKey
                        };
                        protocol = this.getProtocolFromId(authRequest["receiver"]);
                        return [4 /*yield*/, this.createJwt(protocol, password, response, null)];
                    case 1:
                        signedResponse = _a.sent();
                        onSuccess(signedResponse);
                        return [3 /*break*/, 3];
                    case 2:
                        err_1 = _a.sent();
                        onError(err_1);
                        return [3 /*break*/, 3];
                    case 3: return [2 /*return*/];
                }
            });
        }); });
    };
    /*
    * Verify an authentication response.
    *
    * @param {string} AuthResponse The auth response.
    * @param {string} id The identifier.
    *
    * @return {Promise<object>} The verification result.
    */
    AuthID.prototype.verifyAuthResponse = function (authResponse) {
        var _this = this;
        return new Promise(function (onSuccess, onError) { return __awaiter(_this, void 0, void 0, function () {
            var decodedAuthResponse, signer, authPublicKey, signedChallenge, nonce, sharedSecret, challenge, hashedChallenge, verified;
            return __generator(this, function (_a) {
                try {
                    decodedAuthResponse = jsonwebtoken_1.default.decode(authResponse);
                    signer = decodedAuthResponse["signer"];
                    authPublicKey = Buffer.from(decodedAuthResponse["publicKey"], "hex");
                    signedChallenge = decodedAuthResponse["challenge"];
                    if (!this.authChallenges.has(signer))
                        throw new Error("Auth request does not exist.");
                    nonce = this.authChallenges.get(signer);
                    this.authChallenges.delete(signer); // Remove the challenge
                    sharedSecret = this.challengeKey.computeSecret(authPublicKey).toString("hex");
                    challenge = sharedSecret + nonce;
                    hashedChallenge = crypto_1.default.createHash("sha256")
                        .update(challenge)
                        .digest("hex");
                    verified = hashedChallenge == signedChallenge;
                    if (!verified)
                        throw new Error("Failed to authenticate!");
                    onSuccess({ verified: verified, id: signer });
                }
                catch (err) {
                    onError(err);
                }
                return [2 /*return*/];
            });
        }); });
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
        if (id.indexOf(".") > -1) {
            var protocol = id.substring(id.lastIndexOf(".") + 1).toUpperCase();
            ;
            if (!(protocol in this.drivers))
                throw new Error("Unsupported protocol!");
            return protocol;
        }
        throw new Error("Invalid ID!");
    };
    AuthID.prototype.getDriver = function (protocol) {
        return this.drivers[protocol.toUpperCase()];
    };
    AuthID.generateECDH = function () {
        var ecdh = crypto_1.default.createECDH(DH_CURVE);
        ecdh.generateKeys();
        return ecdh;
    };
    return AuthID;
}());
exports.AuthID = AuthID;
