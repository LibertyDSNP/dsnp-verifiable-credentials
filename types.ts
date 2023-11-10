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
