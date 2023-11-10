type JsonLdContext =
  /* Either a string, or an array containing strings and objects with string values */
  | string
  | (
      | string
      | {
          [name: string]: string;
        }
    )[];

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
  [key: string]: any; // Allow additional keys
}

export interface VerifiableCredentialWithEd25519Proof
  extends VerifiableCredential {
  proof: {
    type: "Ed25519Signature2020";
    /**
     * URI of public key, e.g. did:dsnp:{userId}#{keyId}
     */
    verificationMethod: string;
    /**
     * ISO 8601 datetime, e.g. 2023-01-01T12:00:00.000Z
     */
    created: string;
    proofPurpose: "assertionMethod";
    /**
     * multibase-encoded signature
     */
    proofValue: string;
  };
}
