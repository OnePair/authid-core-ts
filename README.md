
# authid-core-ts

> An AuthID reference implementation in typescript.


AuthID is a protocol that allows for platform independent decentralized identifiers to be used for digital signatures and authentication. An AuthID decentralized identifier can either be a straight up [DID](https://w3c-ccg.github.io/did-spec/), or a human meaningful identifier that points to one.

## Api

### Implemented functions:

* **SET_DRIVER(PROTOCOL, DID_METHOD, AUTHID_DRIVER);**
* **GET_ADDRESS(PROTOCOL)**
* **REGISTER_DID(PROTOCOL, PASSWORD)**
* **IMPORT_DID(PROTOCOL, DID)**
* **AUTHORIZE_PROCESSOR(PROTOCOL, PASSWORD, PROCESSOR_ID, PUBLIC_KEY, SIG, AUTH)**
* **IMPORT_PROCESSOR(PROTOCOL, PASSWORD, PROCESSOR_ID, PROCESSOR_TOKEN, PRIVATE_KEY)**
* **REVOKE_PROCESSOR(PROTOCOL, PASSWORD, PROCESSOR_ID)**
* **CREATE_JWT(PROTOCOL, PASSWORD, CLAIMS, EXPIRES_IN)**
* **VERIFY_JWT(JWT, ID)**
* **GET_INFO(PROTOCOL)**

### Icebox

* **REGISTER_NAME(PROTOCOL, PASSWORD, NAME)**
* **IMPORT_NAME(NAME, PASSWORD)**
* **CREATE_AUTH_REQUEST(ID)**
* **SIGN_AUTH_REQUEST(PASSWORD, AUTH_REQUEST)**
* **VERIFY_AUTH_RESPONSE(AUTH_RESPONSE, ID)**

## Usage

### Installation

```npm install```

### Driver setup

```js
import { AuthID } from "authid-core-ts";
import { EthAuthIDDriver } from "authid-eth-driver"; // Import the ethereum driver
import { JsonRpcProvider } from "ethers/providers";

// 1. Create an AuthID instance

let authID = new AuthID();

// 2. Create and initialize the ethereum driver

let rpcProvider = new JsonRpcProvider("<RPC_HOST>");
let ethDriver = new EthAuthIDDriver("<FILE_PATH>", rpcProvider, "<IPFS_HOST>");
await ethDriver.init();

// 3. Add the Ethereum driver to the AuthID instance

const protocol = "eth"
const didMethod = "ethb"

authID.setDriver(protocol, didMethod, athDriver);

```

## Create a new decentralized identifier


```js
// 1) You will need to get the Ethereum address to fund the AuthID account

const password = "password123";


let address = await autID.getAddress(protocol, password);
console.log("address:", address);

// 2) Register a DID

let did = await authID.registerDID(protocol, password);
console.log("Registered DID:", did);

```

## Create and verify JWTs

```js

const claims = {key: "value"}
const expiresIn = "1 year"

// 1) Create a jwt
let jwt = await authID.createJwt(protocol, password, claims, expiresIn);

// 2) Verify the jwt

try {
	let verified = await authID.verifyJwt(jwt, did);
	console.log("Is the jwt valid?", verified);
} catch(err) {
	console.log("JWT is invalid!");
	console.log(err);
}


```

## Build

```npm run build```

## Test

```npm run test```

