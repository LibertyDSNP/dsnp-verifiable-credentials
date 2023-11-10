import type { VerifiableCredential } from "./types.js";
import { sign, verify, setDIDResolver, addToCache } from "./index.js";
import { base58btc } from "multiformats/bases/base58";
import { getResolver, registerDSNPResolver } from "@dsnp/did-resolver";
import { Resolver } from "did-resolver";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { setTimeout } from "timers/promises";

// Accreditor controls the ProofOfPurchase schema and determines which sellers are certified to issue ProofOfPurchase documents
type Actor = {
  keyPair: Ed25519Multikey;
  dsnpUserId: bigint;
};

const accreditor: Actor = {
  keyPair: await Ed25519Multikey.generate({
    controller: "did:dsnp:123456",
  }),
  dsnpUserId: 123456n,
};

const seller: Actor = {
  keyPair: await Ed25519Multikey.generate({
    controller: "did:dsnp:654321",
  }),
  dsnpUserId: 654321n,
};

const fakeSeller: Actor = {
  keyPair: await Ed25519Multikey.generate({
    controller: "did:dsnp:654322",
  }),
  dsnpUserId: 654322n,
};

const buyer: Actor = {
  keyPair: await Ed25519Multikey.generate({
    controller: "did:dsnp:999999",
  }),
  dsnpUserId: 999999n,
};
const skey = await seller.keyPair.export({ publicKey: true });

const actors = new Map()
  .set(accreditor.dsnpUserId, accreditor)
      .set(seller.dsnpUserId, seller)
      .set(fakeSeller.dsnpUserId, fakeSeller)
  .set(buyer.dsnpUserId, buyer);

// Mock a DSNP system DID resolver
registerDSNPResolver(async (dsnpUserId: bigint) => {
  const controller = `did:dsnp:${dsnpUserId}`;
  const output = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: controller,
    assertionMethod: [
      await actors.get(dsnpUserId).keyPair.export({ publicKey: true }),
    ],
  };
  return output;
});

const resolver = new Resolver(getResolver());
setDIDResolver(resolver);

// A full implementation would look at indexed DSNP content to make this determination
const credentialChecker = async (subjectDid: string, attributeSetType: string): Promise<boolean> => {
  // In this example, the seller has been designated a VerifiedSellerPlatform by the accreditor
  if (subjectDid === "did:dsnp:" + seller.dsnpUserId && attributeSetType === "dsnp://" + accreditor.dsnpUserId + "#VerifiedSellerPlatform") return true;
  return false;
};

const unsignedSchemaVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    {
      "@vocab": "dsnp://123456#",
    },
  ],
  id: "https://dsnp.org/schema/examples/proof_of_purchase.json",
  type: ["VerifiableCredential", "JsonSchemaCredential"],
  issuer: "did:dsnp:123456",
  issuanceDate: new Date().toISOString(),
  expirationDate: "2099-01-01T00:00:00.000Z",
  credentialSchema: {
    id: "https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json",
    type: "JsonSchema",
    digestSRI:
      "sha384-S57yQDg1MTzF56Oi9DbSQ14u7jBy0RDdx0YbeV7shwhCS88G8SCXeFq82PafhCrW",
  },
  credentialSubject: {
    type: "JsonSchema",

    jsonSchema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      title: "ProofOfPurchase",
      type: "object",
      properties: {
        credentialSubject: {
          type: "object",
          properties: {
            interactionId: {
              type: "string",
            },
            href: {
              type: "string",
            },
            reference: {
              type: "object",
              properties: {},
            },
          },
          required: ["interactionId", "href", "reference"],
        },
      },
    },

    dsnp: {
      display: {
        label: {
          "en-US": "Verified Purchase",
        },
      },
      trust: {
        oneOf: [
          "dsnp://" + accreditor.dsnpUserId + "#VerifiedBuyerPlatform",
          "dsnp://" + accreditor.dsnpUserId + "#VerifiedSellerPlatform",
        ],
      },
    },
  },
};

const unsignedVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    {
      "@vocab": "dsnp://654321#",
    },
  ],
  type: ["ProofOfPurchase", "VerifiableCredential"],
  issuer: "did:dsnp:654321",
  issuanceDate: new Date().toISOString(),
  credentialSchema: {
    type: "VerifiableCredentialSchema2023",
    id: "https://dsnp.org/schema/examples/proof_of_purchase.json",
  },
  credentialSubject: {
    interactionId: "TBD",
    href: "http://somestore.com/product/999",
    reference: {
      internalTransactionId: "abc-123-def",
    },
  },
};

describe("dsnp-verifiable-credentials", () => {
  it("rejects invalid issuer DID", async () => {
    const testVC = structuredClone(unsignedVC);
    testVC.issuer = "https://unacceptable.com";
    const signedVC = await sign(
      testVC,
      seller.keyPair.signer(),
      "https://unacceptable.com",
    );
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("invalidDid");
  });

  it("rejects if proof not from issuer", async () => {
    const testVC = structuredClone(unsignedVC);
    const signedVC = await sign(
      testVC,
      accreditor.keyPair.signer(),
      "did:dsnp:" +
        accreditor.dsnpUserId +
        "#" +
        accreditor.keyPair.publicKeyMultibase,
    );
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("proofNotFromIssuer");
  });

  it("rejects if signature is from wrong issuer", async () => {
    const testVC = structuredClone(unsignedVC);
    const signedVC = await sign(
      testVC,
      accreditor.keyPair.signer(),
      "did:dsnp:" + seller.dsnpUserId + "#" + seller.keyPair.publicKeyMultibase,
    );
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("signatureFailsVerification");
  });

  it("rejects if credential is expired", async () => {
    const testVC = structuredClone(unsignedVC);
    testVC.expirationDate = new Date().toISOString();
    const signedVC = await sign(
      testVC,
      seller.keyPair.signer(),
      "did:dsnp:" + seller.dsnpUserId + "#" + seller.keyPair.publicKeyMultibase,
    );
    await setTimeout(100);
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("signatureFailsVerification");
  });

  it("rejects if schema URL is not https", async () => {
    const testVC = structuredClone(unsignedVC);
    testVC.credentialSchema.id = "http://insecure.com";
    const signedVC = await sign(
      testVC,
      seller.keyPair.signer(),
      "did:dsnp:" + seller.dsnpUserId + "#" + seller.keyPair.publicKeyMultibase,
    );
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("schemaUrlNotHttps");
  });

  it("rejects if credential schema type is unknown", async () => {
    const testVC = structuredClone(unsignedVC);
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    testSchemaVC.id = testVC.credentialSchema.id = "https://badcache.com";
    testSchemaVC.type = ["SomeOtherType", "VerifiableCredential"];
    addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const signedVC = await sign(
      testVC,
      seller.keyPair.signer(),
      "did:dsnp:" + seller.dsnpUserId + "#" + seller.keyPair.publicKeyMultibase,
    );
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("unknownSchemaType");
  });

  it("rejects if jsonSchema.title does not match a credential type", async () => {
    const testVC = structuredClone(unsignedVC);
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    testSchemaVC.id = testVC.credentialSchema.id = "https://badcache.com";
    testSchemaVC.credentialSubject.jsonSchema.title = "SomeOtherTitle";
    addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const signedVC = await sign(
      testVC,
      seller.keyPair.signer(),
      "did:dsnp:" + seller.dsnpUserId + "#" + seller.keyPair.publicKeyMultibase,
    );
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("credentialTitleMismatch");
  });

  it("rejects if credential does not validate against schema", async () => {
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const testVC = structuredClone(unsignedVC);
    testVC.credentialSubject.href = 123;
    const signedVC = await sign(
      testVC,
      seller.keyPair.signer(),
      "did:dsnp:" + seller.dsnpUserId + "#" + seller.keyPair.publicKeyMultibase,
    );
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("schemaValidationError");
  });

  it("rejects if credential issuer is not trusted", async() => {
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const testVC = structuredClone(unsignedVC);
    testVC.issuer = "did:dsnp:" + fakeSeller.dsnpUserId;
    const signedVC = await sign(testVC, fakeSeller.keyPair.signer(), "did:dsnp:" + fakeSeller.dsnpUserId + "#" + fakeSeller.keyPair.publicKeyMultibase);
    let verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(false);
    expect(verifyResult.reason).toEqual("untrustedIssuer");
  });

  it("works for valid documents", async () => {
    // Sign the schema
    const signedSchemaVC = await sign(
      unsignedSchemaVC,
      accreditor.keyPair.signer(),
      "did:dsnp:" +
        accreditor.dsnpUserId +
        "#" +
        accreditor.keyPair.publicKeyMultibase,
    );

    let verifyResult = await verify(signedSchemaVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(true);

    // Register the schema with the document loader cache
    addToCache({ document: signedSchemaVC, documentUrl: signedSchemaVC.id });

    // Sign a credential that uses the schema
    const signedVC = await sign(
      unsignedVC,
      seller.keyPair.signer(),
      "did:dsnp:" + seller.dsnpUserId + "#" + seller.keyPair.publicKeyMultibase,
    );

    verifyResult = await verify(signedVC, resolver, credentialChecker);
    expect(verifyResult.verified).toEqual(true);
    expect(verifyResult.display).not.toBeNull();
  });
});
