# Overview

This package is a TypeScript implementation of a specific configuration of W3C Verifiable Credentials for use with [DSNP](https://dsnp.org/).

## Background

This work relies upon the following specifications:

* Verifiable Credential Data Model 1.1 (W3C Recommendation)
* Verifiable Credential Data Integrity 1.0 (W3C Working Draft)
* Verifiable Credentials JSON Schema (W3C Working Draft)
* JSON Schema 2020-12

It can be used to generate and verify Verifiable Credentials with proofs based on a DSNP user's `assertionMethod` key pair, for use with DSNP Attribute Set Announcements as well as interaction tags for use within DSNP content and associated applications.

Verification in a DSNP context involves answering several questions:

* Is the credential expired?
* Can the signature on the credential be verified against the issuer's public key published via DSNP?
* Does the credential's claim data validate against the JSON schema specified?
* If the JSON schema itself is signed, is that signature valid and unexpired?
* Is the issuer trusted to issue credentials of this type (as determined by the schema creator)? [not yet implemented]
* How should the validity of the credential be displayed in a social networking user interface? [not yet implemented]

## Cryptography

In alignment with the DSNP specification, `ed25519` is used for cryptographic signatures and verification.
This library generates and verifies Verifiable Credential `DataIntegrity` proofs in the `Multikey` format.

## Dependencies

This library utilizes a number of open source projects and the authors are grateful for the efforts of the following projects:

* [Digital Bazaar](https://www.digitalbazaar.com/)'s libraries for JSON Linked Data, Verifiable Credentials, Data Integrity proofs, Multikeys, and eddsa/ed25519 cryptography
* [Decentralized Identity Foundation](https://identity.foundation/)'s framework for DID resolution
* [Ajv JSON schema validator](https://ajv.js.org/)

# Usage

## Prerequisites

## Signing a Verifiable Credential

To apply a signature, provide a `signer` object with a `sign` function, `algorithm: "Ed25519"`, and a `verificationMethod` representing the full reference to the published public key corresponding to the signature key.

Setup using the Ed25519Multikey library:

```
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";

const dsnpDid = "did:dsnp:123456";
const keyPair = await Ed25519Multikey.generate({ controller: dsnpDid });
const signer = keyPair.signer();
const verificationMethod = dsnpDid + "#" + keyPair.publicKeyMultibase; // format determined by DSNP system
```

Then simply request a signed copy of an instance of the `VerifiableCredential` type:

```
import { signedCopyOf } from "@dsnp/verifiable-credentials";

const signedVC = await signedCopyOf(unsignedVC, signer, verificationMethod);
```

The resulting object is a `VerifiableCredentialWithEd25519Proof`.

## Verifying a Verifiable Credential

 You must pass a DID resolver to the `verify()` method.
For a resolver that can resolve DSNP DIDs, use the `@dsnp/did-resolver` package along with a DSNP system-specific plugin.

```
import { Resolver } from "did-resolver";
import { getResolver } from "@dsnp/did-resolver";
import "dsnp-did-resolver-plugin-{system}";

const resolver = new Resolver(getResolver());
```

Then perform verification:

```
import { verify } from "@dsnp/verifiable-credentials";

const verifyResult = await verify(signedVC, resolver);
if (verifyResult) {
  // Success
}
```

### Implementation notes

In this version, verification will only succeed if the credential is issued from a DSNP DID and the public key is verifiably owned by the DSNP user associated with the DID.
This means that the non-fragment portion of the `verificationMethod` associated with the proof must be the same as the issuer's DID.

This version does not yet support resolution of key ownership via an `alsoKnownAs` alias within the user's DID document.

## Document caching

The library caches credentials, schema credentials, and JSON-LD context files resolved over the network.
Specification-related context files are pre-cached.
It does not cache DID documents, but this can be tuned on the resolver itself.

You can also explicitly add documents to the cache (as strings or objects) using the `addToCache` function.
This is useful for testing, or if you have an application that relies on well known credential documents, for example.

```
import { addToCache } from "@dsnp/verifiable-credentials";

addToCache({
  documentUrl: mySchemaCredentialUrl,
  document: mySignedSchemaCredential
});
```
