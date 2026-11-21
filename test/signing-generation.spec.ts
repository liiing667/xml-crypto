import { SignedXml, type SignatureAlgorithm } from "../src/index";
import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import { expect } from "chai";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

type SigningFailure = Error & {
  keyGeneration?: string | null;
  keyInfo?: string | null;
  location?: string;
  signingFailure?: {
    keyGeneration: string | null;
    keyInfo: string | null;
    location: string;
    stage: string;
  };
  signingStage?: string;
};

const elsewhere = () => new Promise((resolve) => setImmediate(resolve));

class RemoteRsaSha256 implements SignatureAlgorithm {
  getAlgorithmName = () => RSA_SHA256;

  getSignature(): never {
    throw new Error("this algorithm signs only asynchronously");
  }

  verifySignature(): never {
    throw new Error("this algorithm verifies only asynchronously");
  }

  async getSignatureAsync(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike) {
    await elsewhere();
    return crypto.createSign("RSA-SHA256").update(signedInfo).sign(privateKey, "base64");
  }

  async verifySignatureAsync(material: string, key: crypto.KeyLike, signatureValue: string) {
    await elsewhere();
    return crypto.createVerify("RSA-SHA256").update(material).verify(key, signatureValue, "base64");
  }
}

class FailingRsaSha256 extends RemoteRsaSha256 {
  async getSignatureAsync(): Promise<string> {
    throw new Error("signing service unavailable");
  }
}

class FailingRsaSha512 extends RemoteRsaSha256 {
  getAlgorithmName = () => RSA_SHA512;

  async getSignatureAsync(): Promise<string> {
    throw new Error("signing service unavailable");
  }
}

function addRootReference(sig: SignedXml) {
  sig.addReference({
    xpath: "/*",
    transforms: [ENVELOPED, EXCLUSIVE_C14N],
    digestAlgorithm: SHA256,
  });
}

function createSigner(
  privateKey: crypto.KeyLike,
  publicCert: crypto.KeyLike,
  keyInfoLabel: () => string,
): SignedXml {
  const sig = new SignedXml({
    privateKey,
    publicCert,
    canonicalizationAlgorithm: EXCLUSIVE_C14N,
    signatureAlgorithm: RSA_SHA256,
    getKeyInfoContent: () => `<KeyName>${keyInfoLabel()}</KeyName>`,
  });
  addRootReference(sig);
  return sig;
}

function signatureCount(xml: string): number {
  return (xml.match(/<Signature(?:\s|>)/g) ?? []).length;
}

function signatureValueCount(xml: string): number {
  return (xml.match(/<SignatureValue>/g) ?? []).length;
}

describe("signing generation", function () {
  this.timeout(10000);

  const keyA = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const keyB = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const xml = "<root><value>trusted</value></root>";

  async function rejectedFailure(promise: Promise<unknown>): Promise<SigningFailure> {
    try {
      await promise;
    } catch (error) {
      expect(error).to.be.instanceOf(Error);
      return error as SigningFailure;
    }
    throw new Error("expected signing to reject");
  }

  it("publishes only the retry's key, algorithm, and KeyInfo after a failed attempt", async function () {
    let label = "generation-a";
    const signer = createSigner(keyA.privateKey, keyA.publicKey, () => label);
    signer.SignatureAlgorithms[RSA_SHA256] = FailingRsaSha256;

    const firstFailure = await rejectedFailure(signer.computeSignatureAsync(xml));
    expect(signer.getSignedXml()).to.equal("");
    expect(signer.getSignatureXml()).to.equal("");
    expect(firstFailure.signingStage).to.equal("signature");
    expect(firstFailure.location).to.equal("Signature/SignedInfo/SignatureMethod");
    expect(firstFailure.keyGeneration).to.be.a("string");
    expect(firstFailure.keyInfo).to.contain("generation-a");
    expect(firstFailure.signingFailure?.stage).to.equal("signature");

    label = "generation-b";
    signer.privateKey = keyB.privateKey;
    signer.publicCert = keyB.publicKey;
    signer.signatureAlgorithm = RSA_SHA512;
    signer.SignatureAlgorithms[RSA_SHA512] = FailingRsaSha512;

    const secondFailure = await rejectedFailure(signer.computeSignatureAsync(xml));
    expect(signer.getSignedXml()).to.equal("");
    expect(secondFailure.keyInfo).to.contain("generation-b");
    expect(secondFailure.keyGeneration).not.to.equal(firstFailure.keyGeneration);

    signer.SignatureAlgorithms[RSA_SHA512] = new SignedXml().SignatureAlgorithms[RSA_SHA512];
    await signer.computeSignatureAsync(xml);

    const signedXml = signer.getSignedXml();
    expect(signatureCount(signedXml)).to.equal(1);
    expect(signedXml).to.contain('<KeyName>generation-b</KeyName>');
    expect(signedXml).to.contain(`SignatureMethod Algorithm="${RSA_SHA512}"`);

    const verifierB = new SignedXml({ publicCert: keyB.publicKey });
    verifierB.loadSignature(signer.getSignatureXml());
    expect(verifierB.checkSignature(signedXml)).to.be.true;

    const verifierA = new SignedXml({ publicCert: keyA.publicKey });
    verifierA.loadSignature(signer.getSignatureXml());
    expect(() => verifierA.checkSignature(signedXml)).to.throw(/invalid signature/);
  });

  it("clears the previous output and keeps the loaded signature verifiable after a failure", async function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
      canonicalizationAlgorithm: EXCLUSIVE_C14N,
      signatureAlgorithm: RSA_SHA256,
    });
    addRootReference(signer);
    await signer.computeSignatureAsync(xml);
    const firstSignedXml = signer.getSignedXml();
    const firstVerifier = new SignedXml({
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    firstVerifier.loadSignature(signer.getSignatureXml());
    expect(firstVerifier.checkSignature(firstSignedXml)).to.be.true;

    signer.SignatureAlgorithms[RSA_SHA256] = FailingRsaSha256;
    await assert.rejects(signer.computeSignatureAsync("<root><value>new</value></root>"), {
      message: "signing service unavailable",
    });

    expect(signer.getSignedXml()).to.equal("");
    expect(signer.getSignatureXml()).to.equal("");
    expect(signer.checkSignature(firstSignedXml)).to.be.true;
  });

  it("accepts one callback answer and ignores a late success after an error", async function () {
    const privateKey = fs.readFileSync("./test/static/client.pem");
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: EXCLUSIVE_C14N,
      signatureAlgorithm: RSA_SHA256,
    });
    addRootReference(signer);

    class ErrorThenSuccess implements SignatureAlgorithm {
      getAlgorithmName = () => RSA_SHA256;

      verifySignature(): never {
        throw new Error("this algorithm only signs");
      }

      getSignature = function (
        signedInfo: crypto.BinaryLike,
        key: crypto.KeyLike,
        callback?: (error: Error | null, signature?: string) => void,
      ) {
        callback?.(new Error("first answer failed"));
        callback?.(null, crypto.createSign("RSA-SHA256").update(signedInfo).sign(key, "base64"));
      } as unknown as SignatureAlgorithm["getSignature"];
    }

    signer.SignatureAlgorithms[RSA_SHA256] = ErrorThenSuccess;
    const outcomes: string[] = [];
    await new Promise<void>((resolve) => {
      /* eslint-disable-next-line deprecation/deprecation */
      signer.computeSignature(xml, (error) => {
        outcomes.push(error?.message ?? "success");
        resolve();
      });
    });

    expect(outcomes).to.deep.equal(["first answer failed"]);
    expect(signer.getSignedXml()).to.equal("");
  });

  it("inserts one SignatureValue when a signing callback answers twice", async function () {
    const privateKey = fs.readFileSync("./test/static/client.pem");
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: EXCLUSIVE_C14N,
      signatureAlgorithm: RSA_SHA256,
    });
    addRootReference(signer);

    class AnswersTwice implements SignatureAlgorithm {
      getAlgorithmName = () => RSA_SHA256;

      verifySignature(): never {
        throw new Error("this algorithm only signs");
      }

      getSignature = function (
        signedInfo: crypto.BinaryLike,
        key: crypto.KeyLike,
        callback?: (error: Error | null, signature?: string) => void,
      ) {
        const signature = crypto.createSign("RSA-SHA256").update(signedInfo).sign(key, "base64");
        callback?.(null, signature);
        callback?.(null, "second answer");
      } as unknown as SignatureAlgorithm["getSignature"];
    }

    signer.SignatureAlgorithms[RSA_SHA256] = AnswersTwice;
    await new Promise<void>((resolve, reject) => {
      /* eslint-disable-next-line deprecation/deprecation */
      signer.computeSignature(xml, (error) => (error ? reject(error) : resolve()));
    });

    expect(signatureCount(signer.getSignedXml())).to.equal(1);
    expect(signatureValueCount(signer.getSignatureXml())).to.equal(1);
  });
});
