import type { VerifiableCredential, JsonSchema_2020_12 } from "./types.js";
import { DSNPVC } from "./index.js";
import didDsnp from "@dsnp/did-resolver";
import { CachedResolver } from "@digitalbazaar/did-io";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { setTimeout } from "timers/promises";
import { base32 } from "multiformats/bases/base32";
import { sha256 } from "multiformats/hashes/sha2";
import * as json from "multiformats/codecs/json";

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
class MockResolver implements didDsnp.DSNPResolver {
  async resolve(dsnpUserId: bigint) {
    const actor = actors.get(dsnpUserId);
    const assertionMethod = [await actor.keyPair.export({ publicKey: true })];
    const controller = `did:dsnp:${dsnpUserId}`;
    const output = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: assertionMethod[0].controller,
      assertionMethod,
    };
    return output;
  }
}

const simpleSchema: JsonSchema_2020_12 = {
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
};

const unsignedSchemaVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/ns/credentials/undefined-terms/v2",
  ],
  id: "https://dsnp.org/schema/examples/proof_of_purchase_credential.json",
  type: ["VerifiableCredential", "JsonSchemaCredential"],
  issuer: "did:dsnp:123456",
  expirationDate: "2099-01-01T00:00:00.000Z",
  credentialSchema: {
    id: "https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json",
    type: "JsonSchema",
    digestSRI:
      "sha384-S57yQDg1MTzF56Oi9DbSQ14u7jBy0RDdx0YbeV7shwhCS88G8SCXeFq82PafhCrW",
  },
  credentialSubject: {
    type: "JsonSchema",
    jsonSchema: simpleSchema,
    dsnp: {
      display: {
        label: {
          "en-US": "Verified Purchase",
        },
      },
      trust: {
        oneOf: [
          `did:dsnp:${accreditor.dsnpUserId}$VerifiedBuyerPlatform`,
          `did:dsnp:${accreditor.dsnpUserId}$VerifiedSellerPlatform`,
        ],
      },
    },
  },
};

const unsignedAccreditationVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/ns/credentials/undefined-terms/v2",
  ],
  type: ["VerifiedSellerPlatform", "VerifiableCredential"],
  issuer: "did:dsnp:123456",
  //  credentialSchema: {
  //    type: "VerifiableCredentialSchema",
  //    id: "https://dsnp.org/schema/examples/verified_seller_platform_schema.json",
  //  },
  credentialSubject: {
    id: "did:dsnp:654321",
  },
};

const resolver = new CachedResolver();
resolver.use(didDsnp.driver([new MockResolver()]));

const vc = new DSNPVC({ resolver });
const accreditationVC = structuredClone(unsignedAccreditationVC);
await vc.sign(accreditationVC, accreditor.keyPair.signer());

const accreditationU8A = json.encode(accreditationVC);
const accreditationSha256 = await sha256.digest(accreditationU8A);
const accreditationMultihash = base32.encode(accreditationSha256.bytes);

vc.addToCache({
  documentUrl: "mock://accreditation",
  document: accreditationVC,
});

const credentialSchemaUsingJsonSchemaCredential = {
  type: "JsonSchemaCredential",
  id: "https://dsnp.org/schema/examples/proof_of_purchase_credential.json",
};

const credentialSchemaUsingJsonSchema = {
  type: "JsonSchema",
  id: "https://dsnp.org/schema/examples/proof_of_purchase.json",
};

const unsignedVC: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/ns/credentials/undefined-terms/v2",
  ],
  type: ["ProofOfPurchase", "VerifiableCredential"],
  issuer: {
    id: "did:dsnp:654321",
    authority: [
      {
        id: "mock://accreditation",
        rel: `did:dsnp:${accreditor.dsnpUserId}$VerifiedBuyerPlatform`,
        hash: [accreditationMultihash],
      },
    ],
  },
  issuanceDate: new Date().toISOString(),
  credentialSchema: credentialSchemaUsingJsonSchemaCredential,
  credentialSubject: {
    interactionId: "TBD",
    href: "http://somestore.com/product/999",
    reference: {
      internalTransactionId: "abc-123-def",
    },
  },
};

const unsignedVCv2: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/undefined-terms/v2",
  ],
  type: ["ProofOfPurchase", "VerifiableCredential"],
  issuer: {
    id: "did:dsnp:654321",
    authority: [
      {
        id: "mock://accreditation",
        rel: `did:dsnp:${accreditor.dsnpUserId}$VerifiedBuyerPlatform`,
        hash: [accreditationMultihash],
      },
    ],
  },
  validFrom: new Date().toISOString(),
  credentialSchema: credentialSchemaUsingJsonSchemaCredential,
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

  async function testHappyPath(
    testVC: VerifiableCredential,
    testSchemaVC: VerifiableCredential | JsonSchema_2020_12,
    expectedNamespace: string,
  ) {
    // Sign a credential that uses the schema
    const signResult = await vc.sign(testVC, seller.keyPair.signer());
    expect(signResult.signed).toBe(true);

    let verifyResult = await vc.verify(testVC);
    expect(verifyResult.verified).toBe(true);

    if (testVC.credentialSchema.type === "JsonSchemaCredential") {
      expect(verifyResult.display).toStrictEqual(
        unsignedSchemaVC.credentialSubject.dsnp.display,
      );
    }

    // Should still work if we specify the correct attributeSetType
    verifyResult = await vc.verify(
      testVC,
      `${expectedNamespace}$ProofOfPurchase`,
    );
    expect(verifyResult.verified).toBe(true);
    if (testVC.credentialSchema.type === "JsonSchemaCredential") {
      expect(verifyResult.display).toStrictEqual(
        unsignedSchemaVC.credentialSubject.dsnp.display,
      );
    }

    // Should fail if we specify the wrong attributeSetType
    verifyResult = await vc.verify(
      testVC,
      `${expectedNamespace}$SomeOtherType`,
    );
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("incorrectAttributeSetType");

    // Should fail if we specify the wrong attributeSetType issuer
    verifyResult = await vc.verify(testVC, "did:dsnp:666666$ProofOfPurchase");
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.reason).toBe("incorrectAttributeSetType");
  }

  it("works for valid v1 documents using JsonSchemaCredential", async () => {
    const testVC = structuredClone(unsignedVC);
    const testSchemaVC = structuredClone(unsignedSchemaVC);

    // Sign the schema
    const signSchemaResult = await vc.sign(
      testSchemaVC,
      accreditor.keyPair.signer(),
    );
    expect(signSchemaResult.signed).toBe(true);

    let verifyResult = await vc.verify(testSchemaVC);
    expect(verifyResult.verified).toBe(true);

    // Register the schema with the document loader cache
    vc.addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    await testHappyPath(testVC, testSchemaVC, "did:dsnp:123456");
  });

  it("works for valid v1 documents using JsonSchema", async () => {
    const testVC = structuredClone(unsignedVC);
    testVC.credentialSchema = credentialSchemaUsingJsonSchema;

    // Register the schema with the document loader cache
    vc.addToCache({
      document: simpleSchema,
      documentUrl: testVC.credentialSchema.id,
    });

    await testHappyPath(
      testVC,
      simpleSchema,
      "bciqais7o43bo3xl2xqo6ogvj2wpcjb2nuvby57qsyl4h63gqrmtx4ky",
    );
  });

  it("works for valid v2 documents using JsonSchemaCredential", async () => {
    const testVC = structuredClone(unsignedVCv2);
    const testSchemaVC = structuredClone(unsignedSchemaVC);

    // Sign the schema
    const signSchemaResult = await vc.sign(
      testSchemaVC,
      accreditor.keyPair.signer(),
    );
    expect(signSchemaResult.signed).toBe(true);

    let verifyResult = await vc.verify(testSchemaVC);
    expect(verifyResult.verified).toBe(true);

    // Register the schema with the document loader cache
    vc.addToCache({ document: testSchemaVC, documentUrl: testSchemaVC.id });

    await testHappyPath(testVC, testSchemaVC, "did:dsnp:123456");
  });

  it("works for valid v2 documents using JsonSchema", async () => {
    const testVC = structuredClone(unsignedVCv2);
    testVC.credentialSchema = credentialSchemaUsingJsonSchema;

    // Register the schema with the document loader cache
    vc.addToCache({
      document: simpleSchema,
      documentUrl: testVC.credentialSchema.id,
    });

    await testHappyPath(
      testVC,
      simpleSchema,
      "bciqais7o43bo3xl2xqo6ogvj2wpcjb2nuvby57qsyl4h63gqrmtx4ky",
    );
  });
});
