export interface AuthIDDriver {
    getAddress(password: string): Promise<string>;
    registerDID(password: string): Promise<string>;
    importDID(password: string, did: string): Promise<void>;
    registerName(password: string, name: string): Promise<string>;
    importName(name: string): Promise<void>;
    authorizeProcessor(password: string, processorId: string, publicKey: string, sig: boolean, auth: boolean): Promise<string>;
    importProcessor(password: string, processorId: string, processorToken: string, privateKey: string): Promise<void>;
    revokeProcessor(password: string, processorId: string): Promise<void>;
    createJwt(password: string, claims: object, expiresIn: string): Promise<string>;
    verifyJwt(jwt: string, id: string): Promise<object>;
    getInfo(): Promise<object>;
    getPublicKeys(password: string): Promise<object>;
    init(): Promise<void>;
}
