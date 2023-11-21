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

* Is the credential unexpired?
* Can the signature on the credential be verified against the issuer's public key published via DSNP?
* If the credential specifies a schema, does the credential's claim data validate against the JSON schema specified?
* If the JSON schema itself is signed, is that signature valid and unexpired?
* Is the issuer trusted to issue credentials of this type (as determined by the schema creator)?
* How should the validity of the credential be displayed in a social networking user interface?

## Cryptography

In alignment with the DSNP specification, `ed25519` is used for cryptographic signatures and verification.
This library generates and verifies Verifiable Credential `DataIntegrity` proofs in the `Multikey` format.

## Dependencies

This library utilizes a number of open source projects and the authors are grateful for the efforts of the following projects:

* [Digital Bazaar](https://www.digitalbazaar.com/)'s libraries for JSON Linked Data, Verifiable Credentials, Data Integrity proofs, Multikeys, and eddsa/ed25519 cryptography
* [Decentralized Identity Foundation](https://identity.foundation/)'s framework for DID resolution
* [Ajv JSON schema validator](https://ajv.js.org/)

# Usage

## Configuring an instance of DSNPVC

The `DSNPVC` class encapsulates signing and verifying functions, as well as a document cache.
Its constructor takes an object that must contain the following keys:

- `resolver`: An instance of `Resolver` from the `did-resolver` package.

```
import { DSNPVC } from "@dsnp/verifiable-credentials";
import { Resolver } from "did-resolver";
import { getResolver } from "@dsnp/did-resolver";
import { FooPlugin } from "dsnp-did-resolver-plugin-{foo}";

const resolver = new Resolver(getResolver([new FooPlugin(/* options */)]));

const vc = new DSNPVC({ resolver });
```

## Signing a Verifiable Credential

To apply a signature, provide a `signer` object with a `sign` function, `algorithm: "Ed25519"`, and a `verificationMethod` representing the full reference to the published public key corresponding to the signature key.

Setup using the Ed25519Multikey library:

```
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";

const dsnpDid = "did:dsnp:123456";
const keyPair = await Ed25519Multikey.generate({ controller: dsnpDid });
const signer = keyPair.signer();
```

Note: Unless you assign a specific `id` within the `generate()` options, the generated `id` value (and hence `verificationMethod` for the resulting proof) will be set to `${controller}#${publicKeyMultibase}`.

Using this library, you can then request a signature be applied to an instance of the `VerifiableCredential` type:

```
import { DSNPVC } from "@dsnp/verifiable-credentials";

const vc = new DSNPVC({ resolver });

const signResult = await vc.sign(unsignedVC, signer);
if (signResult.signed) {
  // Success
}
```

On failure, `signResult.signed` will be `false` with the relevant error captured in `signResult.reason` and `signResult.context`.

## Verifying a Verifiable Credential

The `verify()` method takes a signed `VerifiableCredential` object and an optional `string` indicating the expected DSNP attribute set type.

To perform verification:

```
import { DSNPVC } from "@dsnp/verifiable-credentials";

const vc = new DSNPVC({ resolver });

const verifyResult = await vc.verify(signedVC, expectedAttributeSetType);
if (verifyResult.verified) {
  // Success
}
```

On failure, `verifyResult.verified` will be `false` with the relevant error captured in `verifyResult.reason` and `verifyResult.context`.

### Implementation notes

In this version, verification will only succeed if the credential is issued from a DSNP DID and the public key is verifiably owned by the DSNP user associated with the DID.
This means that the non-fragment portion of the `verificationMethod` associated with the proof must be the same as the issuer's DID.

This version does not yet support resolution of key ownership via an `alsoKnownAs` alias within the user's DID document.

## Document caching

The library caches credentials, schema credentials, and JSON-LD context files resolved over the network.
Specification-related context files are pre-cached.
It does not cache DID documents, but this can be tuned on the resolver itself.

You can also explicitly add documents to the cache (as strings or objects) using the `addToCache` function.
This is useful for testing, or if you have an application that relies on well known schema documents, for example.

```
vc.addToCache({
  documentUrl: mySchemaCredentialUrl,
  document: mySignedSchemaCredential
});
```

## Attribute Set Type calculation

It is sometimes useful (for instance, when created an Attribute Set Announcement) to generate the DSNP Attribute Set Type for a credential.
This can be done independently from signing or verification with the function `getAttributeSetType`.

```
const attributeSetType = await vc.getAttributeSetType(credentialUrl);
```

If the credential schema document (string or object) is already resolved, you can skip the document loader by passing it in as a second argument:

```
const attributeSetType = await vc.getAttributeSetType(credentialUrl, credentialSchemaDocument);
```
