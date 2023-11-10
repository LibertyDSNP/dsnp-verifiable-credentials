import {
  Resolver,
  DIDDocument,
  VerificationMethod,
  DIDResolutionResult,
  parse,
} from "did-resolver";
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
import { cryptosuite } from "@digitalbazaar/eddsa-2022-cryptosuite";
import * as vc from "@digitalbazaar/vc";
import jsig from "jsonld-signatures";
const { extendContextLoader } = jsig;
import Ajv2020 from "ajv/dist/2020.js"; // Use 2020-12 schema
import jsonld from "jsonld";
import dataIntegrityContext from "@digitalbazaar/data-integrity-context";
import credentialsContext from "credentials-context";

import type { VerifiableCredential } from "./types.js";

export type { VerifiableCredential };

const ajv = new Ajv2020.default();

type loaderCacheType = {
  [schemaUrl: string]: object;
};

const loaderCache: loaderCacheType = {};
const nodeDocumentLoader = jsonld.documentLoaders.node();

export const addToCache = (options: {
  contextUrl?: string;
  document: string | object;
  documentUrl: string;
}) => {
  loaderCache[options.documentUrl] = { ...options };
};

addToCache({
  document: dataIntegrityContext.CONTEXT,
  documentUrl: dataIntegrityContext.CONTEXT_URL,
});
addToCache({
  document: credentialsContext.CONTEXT,
  documentUrl: credentialsContext.CONTEXT_URL,
});

let didResolver: Resolver | null = null;
export const setDIDResolver = (resolver: Resolver) => {
  didResolver = resolver;
};

function dereference(
  document: DIDDocument,
  fragment: string,
): VerificationMethod | null {
  if (!document.assertionMethod) {
    return null;
  }
  const foundMethod = (document.assertionMethod as VerificationMethod[]).find(
    (verificationMethod: VerificationMethod) => {
      return verificationMethod.id.endsWith("#" + fragment);
    },
  );

  if (!foundMethod) {
    console.log("No matching assertionMethod was found for id " + fragment);
    return null;
  }
  return foundMethod;
}

// Document loader used to resolve links in credentials and schema
// TODO currently never expires anything from cache, this should be tuneable
export const documentLoader = extendContextLoader(async (url: string) => {
  const cached = loaderCache[url];
  if (cached) {
    return cached;
  }

  // Resolve DID URLs via the DID resolver framework
  if (url.startsWith("did:")) {
    if (didResolver) {
      const { didDocument } = await didResolver.resolve(url);
      if (didDocument) {
        let document: object | null = didDocument;
        // We have a DIDDocument, but might only need a key identified by fragment
        const parsed = parse(url);
        if (parsed?.fragment) {
          document = dereference(didDocument, parsed.fragment);
        }
        return { document };
      }
    }
  }
  // Fall back to loading from the web
  const output = nodeDocumentLoader(url);
  addToCache(output);
  return output;
});

export type SignResult = {
  signed: boolean;
  reason?: "exception";
  context?: any;
};

export const sign = async (
  credential: VerifiableCredential,
  signer: {
    id: string;
    algorithm: string;
    sign: (obj: any) => Uint8Array;
  },
): Promise<SignResult> => {
  try {
    const suite = new DataIntegrityProof({ signer, cryptosuite });

    await vc.issue({
      credential,
      suite,
      documentLoader,
    });
  } catch (e) {
    return {
      signed: false,
      reason: "exception",
      context: e,
    };
  }

  return { signed: true };
};

const didRegex = new RegExp(
  "^did:[a-z0-9]+(:([-a-zA-Z0-9._]|%[A-F0-9][A-F0-9])+)+$",
);

export type VerifyResult = {
  verified: boolean;
  reason?:
    | "invalidDid"
    | "proofNotFromIssuer"
    | "signatureFailsVerification"
    | "schemaUrlNotHttps"
    | "unknownSchemaType"
    | "credentialTitleMismatch"
    | "schemaValidationError"
    | "untrustedIssuer"
    | "exception";
  context?: any;
  display?: object;
};

export const verify = async (
  credential: VerifiableCredential,
  resolver: { resolve: (did: string) => DIDResolutionResult },
  credentialChecker: (
    subjectDid: string,
    attributeSetType: string,
  ) => Promise<boolean>,
): Promise<VerifyResult> => {
  try {
    // issuer should be a valid DID
    if (!didRegex.test(credential.issuer)) {
      return { verified: false, reason: "invalidDid" };
    }
    // proof.verificationMethod should start with issuer User URI + "#"
    if (
      !credential.proof.verificationMethod.startsWith(credential.issuer + "#")
    ) {
      return { verified: false, reason: "proofNotFromIssuer" };
    }

    const suite = new DataIntegrityProof({ cryptosuite });

    // Perform verification of the signature (does not validate against schema)
    const output = await vc.verifyCredential({
      credential,
      suite,
      documentLoader,
      purpose: {
        validate: (proof: any) => {
          return {
            valid: proof.proofPurpose === "assertionMethod",
          };
        },
        match: (proof: any, { document, documentLoader }: any) => {
          return true;
        },
      },
    });

    if (!output.verified) {
      return {
        verified: false,
        reason: "signatureFailsVerification",
        context: output,
      };
    }

    // Retrieve schema
    const schemaUrl = credential.credentialSchema.id;
    // Only accept HTTPS URLs
    if (!schemaUrl.startsWith("https://")) {
      return { verified: false, reason: "schemaUrlNotHttps" };
    }
    if (
      schemaUrl ===
      "https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json"
    ) {
      // Document we're verifying is a schema VC, no need to check its schema
      return { verified: true };
    }

    const { document: schemaCredential } = await documentLoader(schemaUrl);

    // Ensure that it is a schemaCredential
    if (schemaCredential.type.indexOf("JsonSchemaCredential") == -1) {
      return {
        verified: false,
        reason: "unknownSchemaType",
        context: { type: schemaCredential.type },
      };
    }

    // Check the schema credential's schema title against the type of the VC
    if (
      credential.type.indexOf(
        schemaCredential.credentialSubject.jsonSchema.title,
      ) == -1
    ) {
      return {
        verified: false,
        reason: "credentialTitleMismatch",
        context: {
          title: schemaCredential.credentialSubject.jsonSchema.title,
          type: credential.type,
        },
      };
    }

    // Verify the schema credential's proof
    const schemaVerifyResult = await verify(
      schemaCredential,
      resolver,
      credentialChecker,
    );

    // Validate the credential against its schema
    const valid = ajv.validate(
      schemaCredential.credentialSubject.jsonSchema,
      credential,
    );
    if (!valid) {
      return {
        verified: false,
        reason: "schemaValidationError",
        context: ajv.errors || undefined,
      };
    }

    // Check for required trust chains
    if (schemaCredential.credentialSubject.dsnp?.trust) {
      const trust: any = schemaCredential.credentialSubject.dsnp.trust;
      if (trust.oneOf) {
        const promises: Promise<boolean>[] = [];
        trust.oneOf.forEach((attributeSetType: string) => {
          promises.push(credentialChecker(credential.issuer, attributeSetType));
        });
        const results = await Promise.all(promises);
        if (!results.some((result) => result)) {
          return {
            verified: false,
            reason: "untrustedIssuer",
            context: {
              issuer: credential.issuer,
              oneOf: trust.oneOf,
            },
          };
        }
      }
      if (trust.allOf) {
        const promises: Promise<boolean>[] = [];
        trust.oneOf.forEach((attributeSetType: string) => {
          promises.push(credentialChecker(credential.issuer, attributeSetType));
        });
        const results = await Promise.all(promises);
        if (!results.every((result) => result)) {
          return {
            verified: false,
            reason: "untrustedIssuer",
            context: {
              issuer: credential.issuer,
              oneOf: trust.oneOf,
            },
          };
        }
      }
    }

    // All checks complete
    // TODO cache?
    return {
      verified: true,
      display: schemaCredential.credentialSubject.dsnp?.display,
    };
  } catch (e) {
    return {
      verified: false,
      reason: "exception",
      context: e,
    };
  }
};
