# Overview

This package is a TypeScript implementation of specific configurations of W3C Verifiable Credentials for use with [DSNP](https://dsnp.org/).

## Background

This work relies upon the following specifications:

* [Verifiable Credential Data Model 1.1 (W3C Recommendation 03 March 2022)](https://www.w3.org/TR/2022/REC-vc-data-model-20220303/)
* [Verifiable Credential Data Model 2.0 (W3C Candidate Recommendation Draft 09 August 2024)](https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240809/)
* [Verifiable Credential Data Integrity 1.0 (W3C Candidate Recommendation Draft 03 August 2024)](https://www.w3.org/TR/2024/CRD-vc-data-integrity-20240803/)
* [Verifiable Credentials JSON Schema (W3C Candidate Recommendation Draft 18 December 2023)](https://www.w3.org/TR/2023/CRD-vc-json-schema-20231218/)
* [JSON Schema 2020-12](https://json-schema.org/specification)
* [Decentralized Identifiers (DIDs) v1.0 (W3C Recommendation 19 July 2022)](https://www.w3.org/TR/2022/REC-did-core-20220719/)

### Summary of Supported Configurations

#### Verifiable Credential Document

- The first item in `"@context"` MUST be `"https://www.w3.org/2018/credentials/v1"` or `"https://www.w3.org/ns/credentials/v2"`
- `"type"` MUST include `"VerifiableCredential"`
- `credentialSchema.id` MUST be a `https://` URL
- `credentialSchema.type` MUST be either `"JsonSchema"` or `"JsonSchemaCredential"`
- `issuer` (if a string) or `issuer.id` MUST be a valid DID and start with `did:`
- `proof.verificationMethod` MUST start with the issuer DID followed by the `#` character

#### Verifiable Credential Schema Document

- all of the above requirements for a Verifiable Credential Document MUST be adhered to
- `"type"` MUST include `"JsonSchemaCredential"`
- `credentialSchema.id` MUST be `"https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json"`
- `credentialSchema.type` MUST be `"JsonSchema"`
- `credentialSchema.digestSRI` SHOULD be `"sha384-S57yQDg1MTzF56Oi9DbSQ14u7jBy0RDdx0YbeV7shwhCS88G8SCXeFq82PafhCrW"`, but this is not checked
- `credentialSubject.type` MUST be `"JsonSchema"` and include an embedded JSON Schema Document in `credentialSubject.jsonSchema`.

#### JSON Schema Document (Standalone or Embedded)

- `"$schema"` MUST be `"https://json-schema.org/draft/2020-12/schema"` 

## Relationship to DSNP

This library can be used to generate and verify Verifiable Credentials with proofs based on a DSNP user's `assertionMethod` key pair, for use with DSNP Attribute Set Announcements as well as interaction and attestation attachments for use within DSNP content and associated applications.

Verification in a DSNP context involves answering several questions:

* Is the credential unexpired?
* Can the signature on the credential be verified against the issuer's public key published via DSNP?
* If the credential specifies a schema, does the credential's claim data validate against the JSON schema specified?
* If the JSON schema itself is a signed JsonSchemaCredential, is that signature valid and unexpired?
* Is the issuer trusted to issue credentials of this type (as determined by the schema creator)? (DSNP extension)
* How should the validity of the credential be displayed in a social networking user interface? (DSNP extension)

## Cryptography

In alignment with the DSNP specification, `ed25519` is used for cryptographic signatures and verification.
This library generates and verifies Verifiable Credential `DataIntegrity` proofs in the `Multikey` format.

## Dependencies

This library utilizes a number of open source projects and the authors are grateful for the efforts of the following projects:

* [Digital Bazaar](https://www.digitalbazaar.com/)'s libraries for DID resolution, JSON Linked Data, Verifiable Credentials, Data Integrity proofs, Multikeys, and eddsa/ed25519 cryptography
* [Ajv JSON schema validator](https://ajv.js.org/)

# Usage

## Configuring an instance of DSNPVC

The `DSNPVC` class encapsulates signing and verifying functions, as well as a document cache.
Its constructor takes an object that must contain the following keys:

- `resolver`: An instance of `CachedResolver` from the `@digitalbazaar/did-io` package.

```
import { DSNPVC } from "@dsnp/verifiable-credentials";
import { CachedResolver } from "@digitalbazaar/did-io";
import didDsnp from "@dsnp/did-resolver";
import { FooResolver } from "dsnp-did-resolver-{foo}";

const resolver = new CachedResolver();
resolver.use(didDsnp.driver([new FooResolver(/* options */)]));

const vc = new DSNPVC({ resolver });
```

## Signing a Verifiable Credential

To apply a signature, provide a `signer` object with a `sign` function, `algorithm: "Ed25519"`, and an `id` representing the full reference to the published public key corresponding to the signature key.

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

It is sometimes useful (for instance, when creating an Attribute Set Announcement) to generate the DSNP Attribute Set Type for a credential.
This can be done independently from signing or verification with the function `getAttributeSetType`.

```
const attributeSetType = await vc.getAttributeSetType(credentialUrl);
```

If the credential schema document (string or object) is already resolved, you can skip the document loader by passing it in as a second argument:

```
const attributeSetType = await vc.getAttributeSetType(credentialUrl, credentialSchemaDocument);
```
