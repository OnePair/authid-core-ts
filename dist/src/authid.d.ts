import { AuthIDDriver } from "./authid-driver";
export declare class AuthID {
    private drivers;
    private didMethods;
    constructor();
    setDriver(protocol: string, didMethod: string, authIDDriver: AuthIDDriver): void;
    getAddress(protocol: string, password: string): Promise<string>;
    registerDID(protocol: string, password: string): Promise<string>;
    importDID(password: string, did: string): Promise<void>;
    registerName(protocol: string, password: string, name: string): Promise<string>;
    importName(name: string): Promise<void>;
    authorizeProcessor(protocol: string, password: string, processorId: string, publicKey: string, sig: boolean, auth: boolean): Promise<string>;
    importProcessor(protocol: string, password: string, processorId: string, processorToken: string, privateKey: string): Promise<void>;
    revokeProcessor(protocol: string, password: string, processorId: string): Promise<void>;
    createJwt(protocol: string, password: string, claims: object, expiresIn: string): Promise<string>;
    verifyJwt(jwt: string, id: string): Promise<object>;
    getInfo(protocol: string): Promise<object>;
    getPublicKeys(protocol: string, password: string): Promise<object>;
    getProtocolFromId(id: string): string;
    private getDriver;
}
