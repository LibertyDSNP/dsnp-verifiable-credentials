declare module "@digitalbazaar/vc" {
  export function defaultDocumentLoader(url: string): any;
  export function issue(params: any): any;
  export function verifyCredential(options: any): any;
}

declare module "jsonld-signatures" {
  export function extendContextLoader(extension: (string) => any);
}

declare module "@digitalbazaar/data-integrity" {
  export class DataIntegrityProof {
    constructor(options: any);
    verificationMethod: string;
  }
}

declare module "@digitalbazaar/data-integrity-context" {
  export const CONTEXT: object;
  export const CONTEXT_URL: string;
}

declare module "@digitalbazaar/ed25519-multikey" {}

declare module "@digitalbazaar/eddsa-rdfc-2022-cryptosuite" {
  export const cryptosuite: object;
}

declare module "jsonld" {
  export const documentLoaders: { node: () => any };
}

declare module "@digitalbazaar/credentials-context" {
  export const named: Map;
}
