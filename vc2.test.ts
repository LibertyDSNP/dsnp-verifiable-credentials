import type { VerifiableCredential } from "./types.js";
import { DSNPVC } from "./index.js";
import { base58btc } from "multiformats/bases/base58";
import { DSNPResolver, getResolver } from "@dsnp/did-resolver";
import { Resolver } from "did-resolver";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { setTimeout } from "timers/promises";

type Actor = {
  keyPair: Ed25519Multikey;
  dsnpUserId: bigint;
};

async function makeActor(dsnpUserId: bigint, isAccredited: boolean): Actor {
  return {
    keyPair: await Ed25519Multikey.generate({
      controller: `did:dsnp:${dsnpUserId}`,
    }),
    dsnpUserId,
    isAccredited,
  };
}

// Accreditor controls the ProofOfPurchase schema and determines which sellers are certified to issue ProofOfPurchase documents
const accreditor = await makeActor(123456n);
const seller = await makeActor(654321n, true);
const fakeSeller = await makeActor(654322n);
const buyer = await makeActor(999999n, true);

const actors = new Map()
  .set(accreditor.dsnpUserId, accreditor)
  .set(seller.dsnpUserId, seller)
  .set(fakeSeller.dsnpUserId, fakeSeller)
  .set(buyer.dsnpUserId, buyer);

// Mock a DSNP system DID resolver
class MockResolver implements DSNPResolver {
  async resolve(dsnpUserId: bigint) {
    const actor = actors.get(dsnpUserId);
    const assertionMethod = [await actor.keyPair.export({ publicKey: true })];
    const controller = `did:dsnp:${dsnpUserId}`;
    const service = actor.isAccredited
      ? [
          {
            id:
              controller +
              "#" +
              encodeURIComponent(
                `did:dsnp:${accreditor.dsnpUserId}#VerifiedSellerPlatform`,
              ),
            type: "DSNPAttributeSet",
            serviceEndpoint: "mock://accreditation",
          },
        ]
      : null;
    const output = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: assertionMethod[0].controller,
      assertionMethod,
      service,
    };
    return output;
  }
}

const unsignedSchemaVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
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
          `did:dsnp:${accreditor.dsnpUserId}#VerifiedBuyerPlatform`,
          `did:dsnp:${accreditor.dsnpUserId}#VerifiedSellerPlatform`,
        ],
      },
    },
  },
};

const unsignedVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
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

const unsignedAccreditationVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    {
      "@vocab": "dsnp://123456#",
    },
  ],
  type: ["VerifiedSellerPlatform", "VerifiableCredential"],
  issuer: "did:dsnp:123456",
  issuanceDate: new Date().toISOString(),
  //  credentialSchema: {
  //    type: "VerifiableCredentialSchema2023",
  //    id: "https://dsnp.org/schema/examples/proof_of_purchase.json",
  //  },
  credentialSubject: {
    id: "did:dsnp:654321",
  },
};

const resolver = new Resolver(getResolver([new MockResolver()]));

const vc = new DSNPVC({ resolver });
const accreditationVC = structuredClone(unsignedAccreditationVC);
vc.sign(accreditationVC, accreditor.keyPair.signer());

vc.addToCache({
  documentUrl: "mock://accreditation",
  document: accreditationVC,
});

describe("dsnp-verifiable-credentials", () => {
  it("rejects invalid issuer DID", async () => {
    const testVC = structuredClone(unsignedVC);

    // Example key from @digitalbazaar/data-integrity README
    const controller = "https://example.edu/issuers/565049";
    const keyPair = await Ed25519Multikey.from({
      "@context": "https://w3id.org/security/multikey/v1",
      type: "Multikey",
      controller,
      id: controller + "#z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT",
      publicKeyMultibase: "z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT",
      secretKeyMultibase:
        "zrv3rbPamVDGvrm7LkYPLWYJ35P9audujKKsWn3x29EUiGwwhdZQd" +
        "1iHhrsmZidtVALBQmhX3j9E5Fvx6Kr29DPt6LH",
    });

    testVC.issuer = controller;
    const signResult = await vc.sign(testVC, keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("invalidDid");
  });

  it("rejects if proof not from issuer", async () => {
    const testVC = structuredClone(unsignedVC);
    const signResult = await vc.sign(testVC, accreditor.keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("proofNotFromIssuer");
  });

  it("rejects if signature is from wrong issuer", async () => {
    const testVC = structuredClone(unsignedVC);
    const signResult = await vc.sign(testVC, accreditor.keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("proofNotFromIssuer");
  });

  it("rejects if credential is expired", async () => {
    const testVC = structuredClone(unsignedVC);
    testVC.expirationDate = new Date().toISOString();
    const signResult = await vc.sign(testVC, seller.keyPair.signer());
    expect(signResult.signed).toBe(true);
    await setTimeout(100);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("signatureFailsVerification");
  });

  it("rejects if schema URL is not https", async () => {
    const testVC = structuredClone(unsignedVC);
    testVC.credentialSchema.id = "http://insecure.com";
    const signResult = await vc.sign(testVC, seller.keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("schemaUrlNotHttps");
  });

  it("rejects if credential schema type is unknown", async () => {
    const testVC = structuredClone(unsignedVC);
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    testSchemaVC.id = testVC.credentialSchema.id = "https://badcache.com";
    testSchemaVC.type = ["SomeOtherType", "VerifiableCredential"];
    vc.addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const signResult = await vc.sign(testVC, seller.keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("unknownSchemaType");
  });

  it("rejects if jsonSchema.title does not match a credential type", async () => {
    const testVC = structuredClone(unsignedVC);
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    testSchemaVC.id = testVC.credentialSchema.id = "https://badcache.com";
    testSchemaVC.credentialSubject.jsonSchema.title = "SomeOtherTitle";
    vc.addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const signResult = await vc.sign(testVC, seller.keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("credentialTitleMismatch");
  });

  it("rejects if credential does not validate against schema", async () => {
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    vc.addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const testVC = structuredClone(unsignedVC);
    testVC.credentialSubject.href = 123;
    const signResult = await vc.sign(testVC, seller.keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("schemaValidationError");
  });

  it("rejects if credential issuer is not trusted", async () => {
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    vc.addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    const testVC = structuredClone(unsignedVC);
    testVC.issuer = "did:dsnp:" + fakeSeller.dsnpUserId;
    const signResult = await vc.sign(testVC, fakeSeller.keyPair.signer());
    expect(signResult.signed).toBe(true);
    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("untrustedIssuer");
  });

  it("works for valid documents", async () => {
    const testVC = structuredClone(unsignedVC);
    const testSchemaVC = structuredClone(unsignedSchemaVC);
    // Sign the schema
    const signSchemaResult = await vc.sign(
      testSchemaVC,
      accreditor.keyPair.signer(),
    );
    expect(signSchemaResult.signed).toBe(true);
    console.log(JSON.stringify(testSchemaVC, null, 2));
    let verifyResult = await vc.verify(testSchemaVC);
    expect(verifyResult.verified).toBe(true);

    // Register the schema with the document loader cache
    vc.addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    // Sign a credential that uses the schema
    const signResult = await vc.sign(testVC, seller.keyPair.signer());
    expect(signResult.signed).toBe(true);

    verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(true);
    expect(verifyResult.display).toStrictEqual(
      unsignedSchemaVC.credentialSubject.dsnp.display,
    );

    // Should still work if we specify the correct attributeSetType
    verifyResult = await vc.verify(testVC, "did:dsnp:123456#ProofOfPurchase");
    expect(verifyResult.verified).toBe(true);
    expect(verifyResult.display).toStrictEqual(
      unsignedSchemaVC.credentialSubject.dsnp.display,
    );

    // Should fail if we specify the wrong attributeSetType #type
    verifyResult = await vc.verify(testVC, "did:dsnp:123456#SomeOtherType");
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("incorrectAttributeSetType");

    // Should fail if we specify the wrong attributeSetType issuer
    verifyResult = await vc.verify(testVC, "did:dsnp:123457#ProofOfPurchase");
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("incorrectAttributeSetType");
  }, 10_000);
});
