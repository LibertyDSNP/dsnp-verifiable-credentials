import {
  DIDDocument,
  DIDResolutionResult,
  parse,
  Resolver,
  Service,
  VerificationMethod,
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
import { sha256 } from "multiformats/hashes/sha2";
import { base58btc } from "multiformats/bases/base58";

type JsonLdContext =
  /* Either a string, or an array containing strings and objects with string values */
  string | (string | { [name: string]: string })[];

export interface VerifiableCredential {
  "@context": JsonLdContext;
  id?: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSchema: {
    type: "VerifiableCredentialSchema2023" | "JsonSchema";
    id: string;
    digestSRI?: string;
    [key: string]: any; // Allow additional keys
  };
  credentialSubject: {
    [key: string]: any;
  };
  proof?: {
    verificationMethod: string;
    [key: string]: any;
  };
  [key: string]: any; // Allow additional keys
}

const ajv = new Ajv2020.default();
const nodeDocumentLoader = jsonld.documentLoaders.node();

/**
 * Finds an assertionMethod within the DID document with a matching
 * fragment identifier.
 */
function findAssertionMethod(
  document: DIDDocument,
  fragment: string,
): VerificationMethod | null {
  if (!document.assertionMethod) {
    return null;
  }
  // TODO allow for single assertionMethod as well as array?
  const foundMethod = (document.assertionMethod as VerificationMethod[]).find(
    (verificationMethod: VerificationMethod) => {
      return verificationMethod.id.endsWith("#" + fragment);
    },
  );

  return foundMethod || null;
}

function findService(document: DIDDocument, fragment: string): Service | null {
  if (!document.service) {
    return null;
  }
  // TODO allow for single service as well as array?
  const foundService = (document.service as Service[]).find(
    (service: Service) => {
      return service.id.endsWith("#" + encodeURIComponent(fragment));
    },
  );
  return foundService || null;
}

export type SignResult = {
  signed: boolean;
  reason?: "exception";
  context?: any;
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
    | "unresolvableDid"
    | "fileNotFound"
    | "incorrectAttributeSetType"
    | "exception";
  context?: any;
  display?: object;
};

type DocumentLoaderResult = {
  document: string | object,
  documentUrl: string,
  contextUrl: string | null,
};
  
export class DSNPVC {
  private loaderCache: { [schemaUrl: string]: object } = {};
  private didResolver: Resolver | null;
  private documentLoader: (url: string) => Promise<DocumentLoaderResult>;

  constructor(options: { resolver: null | Resolver }) {
    this.addToCache({
      document: dataIntegrityContext.CONTEXT,
      documentUrl: dataIntegrityContext.CONTEXT_URL,
    });
    this.addToCache({
      document: credentialsContext.CONTEXT,
      documentUrl: credentialsContext.CONTEXT_URL,
    });

    this.didResolver = options.resolver;

    // Document loader used to resolve links in credentials and schema
    // TODO currently never expires anything from cache, this should be tuneable
    this.documentLoader = extendContextLoader(async (url: string) => {
      const cached = this.loaderCache[url];
      if (cached) {
        return cached;
      }

      // Resolve DID URLs via the DID resolver framework
      if (url.startsWith("did:")) {
        if (this.didResolver) {
          const { didDocument } = await this.didResolver.resolve(url);
          if (didDocument) {
            let document: object | null = didDocument;
            // We have a DIDDocument, but might only need a key identified by fragment
            const parsed = parse(url);
            if (parsed?.fragment) {
              document = findAssertionMethod(didDocument, parsed.fragment);
              //TODO deal with null value here?
            }
            return { document };
          }
        }
      }
      // Fall back to loading from the web
      const output = nodeDocumentLoader(url);
      this.addToCache(output);
      return output;
    });
  }

  async sign(
    credential: VerifiableCredential,
    signer: {
      id: string;
      algorithm: string;
      sign: (obj: any) => Uint8Array;
    },
  ): Promise<SignResult> {
    try {
      const suite = new DataIntegrityProof({ signer, cryptosuite });

      await vc.issue({
        credential,
        suite,
        documentLoader: this.documentLoader,
      });
    } catch (e) {
      return {
        signed: false,
        reason: "exception",
        context: e,
      };
    }

    return { signed: true };
  }

  async verify(credential: VerifiableCredential, attributeSetType: string | null = null): Promise<VerifyResult> {
    try {
      // issuer should be a valid DID
      if (!didRegex.test(credential.issuer)) {
        return { verified: false, reason: "invalidDid" };
      }
      // proof.verificationMethod should start with issuer User URI + "#"
      if (
        !credential.proof?.verificationMethod.startsWith(
          credential.issuer + "#",
        )
      ) {
        return { verified: false, reason: "proofNotFromIssuer" };
      }

      const suite = new DataIntegrityProof({ cryptosuite });

      // Perform verification of the signature (does not validate against schema)
      const output = await vc.verifyCredential({
        credential,
        suite,
        documentLoader: this.documentLoader,
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
      // TODO should we allow credentials with no schema?
      if (credential.credentialSchema) {
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

        const { document: schemaDocument } = await this.documentLoader(schemaUrl);
        const schemaCredential = (typeof schemaDocument === "string" ? JSON.parse(schemaDocument) : schemaDocument);
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
        const schemaVerifyResult = await this.verify(schemaCredential);

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
            const promises: Promise<VerifyResult>[] = [];
            trust.oneOf.forEach((attributeSetType: string) => {
              promises.push(
                this.resolveAndVerifyCredential(
                  credential.issuer,
                  attributeSetType,
                ),
              );
            });
            const results = await Promise.all(promises);
            if (!results.some((result) => result.verified)) {
              return {
                verified: false,
                reason: "untrustedIssuer",
                context: {
                  issuer: credential.issuer,
                  oneOf: trust.oneOf,
                  results,
                },
              };
            }
          }
          if (trust.allOf) {
            const promises: Promise<VerifyResult>[] = [];
            trust.oneOf.forEach((attributeSetType: string) => {
              promises.push(
                this.resolveAndVerifyCredential(
                  credential.issuer,
                  attributeSetType,
                ),
              );
            });
            const results = await Promise.all(promises);
            if (!results.every((result) => result.verified)) {
              return {
                verified: false,
                reason: "untrustedIssuer",
                context: {
                  issuer: credential.issuer,
                  oneOf: trust.oneOf,
                  results,
                },
              };
            }
          }
        } // has trust section

        // Check attributeSetType matches, if specified
        if (attributeSetType) {
          const credentialAttributeSetType = await this.getAttributeSetType(credential, schemaDocument);
          if (attributeSetType !== credentialAttributeSetType) {
            return {
              verified: false,
              reason: "incorrectAttributeSetType",
              context: {
                attributeSetType,
                credentialAttributeSetType,
              }
            };
          }
        }
        return {
          verified: true,
          display: schemaCredential.credentialSubject.dsnp?.display,
        };
      } // has schema

      // All checks complete
      // TODO cache the result?
      return {
        verified: true,
      };
    } catch (e) {
      console.log(e);
      return {
        verified: false,
        reason: "exception",
        context: e,
      };
    }
  }

  async resolveAndVerifyCredential(
    did: string,
    attributeSetType: string,
  ): Promise<VerifyResult> {
    let context: {
      [key: string]: object | string;
    } = {
      did,
      attributeSetType,
    };
    if (this.didResolver) {
      const { didDocument, didResolutionMetadata } =
        await this.didResolver.resolve(did);
      if (didDocument) {
        let service = findService(didDocument, attributeSetType);
        if (service && service.serviceEndpoint) {
          // TODO verify hash of retrieved document (if not IPFS)?
          const endpoint: string = Array.isArray(service.serviceEndpoint)? service.serviceEndpoint[0] : service.serviceEndpoint;
          let { document } = await this.documentLoader(endpoint);
          if (!document)
            return {
              verified: false,
              reason: "fileNotFound",
              context: service,
            };
          const documentObj = (typeof document === "string") ? JSON.parse(document) : document;
          // TODO verify that it is a VerifiableCredential before the "as"?
          const accreditationCheckResult = await this.verify(
            documentObj as VerifiableCredential,
          );
          if (accreditationCheckResult.verified) {
            return accreditationCheckResult;
          } else {
            return {
              verified: false,
              reason: "untrustedIssuer",
              context: {
                issuerCredential: document,
                verifyResult: accreditationCheckResult,
              },
            };
          }
        } else {
          context["errorDetail"] =
            "Could not find service[].serviceEndpoint for credential in document";
          if (didDocument.service) {
            context["service"] = didDocument.service;
          }
        }
      } else {
        context["didResolutionMetadata"] = didResolutionMetadata;
      }
    }
    return {
      verified: false,
      reason: "unresolvableDid",
      context,
    };
  }

  addToCache(options: {
    contextUrl?: string;
    document: string | object;
    documentUrl: string;
  }) {
    this.loaderCache[options.documentUrl] = { ...options };
  }

  /**
   * Returns the (claimed) attributeSetType to use for a given credential, following the DSNP algorithm.
   * Note that this function does not perform verification of any kind; use the verify() method for that.
   */
  async getAttributeSetType(credential: VerifiableCredential, schemaDocument: object | string | null = null): Promise<string> {
    const vcType: string = credential.type.find((type) => type !== "VerifiableCredential") || "";

    // Schema-less credentials use first type (if any)
    if (!credential.credentialSchema) return "#" + vcType;

    // Determine if the credentialSchema document is signed
    const { document } = schemaDocument ? { document: schemaDocument } : await this.documentLoader(credential.credentialSchema.id);
    let schemaCredential: VerifiableCredential;
    let schemaCredentialString: string | null = null;
    if (typeof document === "string") {
      schemaCredential = JSON.parse(document);
      schemaCredentialString = document;
    } else {
      schemaCredential = document as VerifiableCredential;
    }
    if ((schemaCredential.type.indexOf("JsonSchemaCredential") == -1) || !schemaCredential.proof) {
      // Not a signed schema credential: calculate the sha2-256 hash only
      // attributeSetType = {hash}#{vcType}
      const message = new TextEncoder().encode(schemaCredentialString || JSON.stringify(schemaCredential));
      return base58btc.encode(await sha256.encode(message)) + "#" + vcType;
    }

    // attributeSetType = {issuer}#{vcType}
    return schemaCredential.issuer + "#" + vcType;
  }
}
