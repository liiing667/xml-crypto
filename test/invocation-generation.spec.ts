import { SignedXml, type SignatureAlgorithm } from "../src/index";
import * as crypto from "crypto";
import * as fs from "fs";
import { expect } from "chai";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

const privateKey = fs.readFileSync("./test/static/client.pem");
const publicCert = fs.readFileSync("./test/static/client_public.pem");

function createSigner(algorithm?: new () => SignatureAlgorithm): SignedXml {
  const sig = new SignedXml({
    privateKey,
    publicCert,
    canonicalizationAlgorithm: EXCLUSIVE_C14N,
    signatureAlgorithm: RSA_SHA256,
  });
  sig.addReference({
    xpath: "//*[local-name(.)='value']",
    transforms: [ENVELOPED, EXCLUSIVE_C14N],
    digestAlgorithm: SHA256,
  });
  if (algorithm) {
    sig.SignatureAlgorithms[RSA_SHA256] = algorithm;
  }
  return sig;
}

function signatureCount(xml: string): number {
  return (xml.match(/<Signature(?:\s|>)/g) ?? []).length;
}

describe("Invocation generation", function () {
  it("re-signing starts a fresh ID sequence and publishes only the new document", function () {
    const signer = createSigner();

    signer.computeSignature("<root><value>first</value></root>");
    expect(signer.getSignedXml()).to.contain('<value Id="_0">first</value>');

    signer.computeSignature("<root><value>second</value></root>");
    const signedXml = signer.getSignedXml();

    expect(signedXml).to.contain('<value Id="_0">second</value>');
    expect(signedXml).not.to.contain("first");
    expect(signatureCount(signedXml)).to.equal(1);
  });

  it("a failed retry exposes nothing and a later success exposes its own document", function () {
    const signer = createSigner();
    signer.computeSignature("<root><value>first</value></root>");
    const firstSignedXml = signer.getSignedXml();

    signer.privateKey = publicCert;
    expect(() => signer.computeSignature("<root><value>failed</value></root>")).to.throw();
    expect(signer.getSignedXml()).to.equal("");
    expect(signer.getSignatureXml()).to.equal("");
    expect(signer.checkSignature(firstSignedXml)).to.be.true;

    signer.privateKey = privateKey;
    signer.computeSignature("<root><value>third</value></root>");
    const signedXml = signer.getSignedXml();

    expect(signedXml).to.contain('<value Id="_0">third</value>');
    expect(signedXml).not.to.contain("first");
    expect(signedXml).not.to.contain("failed");
    expect(signatureCount(signedXml)).to.equal(1);
  });

  it("keeps a verified loaded signature usable after a later signing attempt fails", function () {
    const firstSigner = createSigner();
    firstSigner.computeSignature("<root><value>trusted</value></root>");
    const signedXml = firstSigner.getSignedXml();

    const signer = createSigner();
    signer.loadSignature(firstSigner.getSignatureXml());
    expect(signer.checkSignature(signedXml)).to.be.true;

    expect(() => signer.computeSignature("<root><missing/></root>")).to.throw();
    expect(signer.checkSignature(signedXml)).to.be.true;
    expect(signer.getSignedReferences()).to.deep.equal(['<value Id="_0">trusted</value>']);
  });

  it("does not publish a late verification callback into a newer signing generation", function () {
    let answer: ((error: Error | null, isValid?: boolean) => void) | undefined;

    class DeferredVerificationRsaSha256 implements SignatureAlgorithm {
      getAlgorithmName = () => RSA_SHA256;

      getSignature(signedInfo: crypto.BinaryLike, key: crypto.KeyLike): string {
        return crypto.createSign("RSA-SHA256").update(signedInfo).sign(key, "base64");
      }

      verifySignature = function (
        _material: string,
        _key: crypto.KeyLike,
        _signatureValue: string,
        callback?: (error: Error | null, isValid?: boolean) => void,
      ) {
        answer = callback;
      } as unknown as SignatureAlgorithm["verifySignature"];
    }

    const firstSigner = createSigner();
    firstSigner.computeSignature("<root><value>verified</value></root>");
    const signedFirst = firstSigner.getSignedXml();

    const signer = createSigner(DeferredVerificationRsaSha256);
    signer.loadSignature(firstSigner.getSignatureXml());
    /* eslint-disable-next-line deprecation/deprecation */
    signer.checkSignature(signedFirst, () => {});
    expect(answer).to.be.a("function");

    signer.computeSignature('<root><value Id="_0">current</value></root>');
    const signedCurrent = signer.getSignedXml();
    expect(signedCurrent).to.contain('<value Id="_0">current</value>');
    expect(signedCurrent).not.to.contain("verified");

    answer?.(null, true);

    expect(signer.getSignedXml()).to.equal(signedCurrent);
    expect(signer.getSignedReferences()).to.be.empty;
    expect(signatureCount(signer.getSignedXml())).to.equal(1);
  });

  it("does not publish a late signing callback into a newer signing generation", async function () {
    const pending: Array<{
      signedInfo: crypto.BinaryLike;
      key: crypto.KeyLike;
      callback: (error: Error | null, signature?: string) => void;
    }> = [];

    class DeferredSigningRsaSha256 implements SignatureAlgorithm {
      getAlgorithmName = () => RSA_SHA256;

      verifySignature(): never {
        throw new Error("this algorithm only signs");
      }

      getSignature = function (
        signedInfo: crypto.BinaryLike,
        key: crypto.KeyLike,
        callback?: (error: Error | null, signature?: string) => void,
      ) {
        if (callback) {
          pending.push({ signedInfo, key, callback });
        }
      } as unknown as SignatureAlgorithm["getSignature"];
    }

    const signer = createSigner(DeferredSigningRsaSha256);
    const outcomes: string[] = [];
    /* eslint-disable-next-line deprecation/deprecation */
    signer.computeSignature("<root><value>first</value></root>", (error) => {
      outcomes.push(error ? "error" : "success");
    });
    /* eslint-disable-next-line deprecation/deprecation */
    signer.computeSignature("<root><value>second</value></root>", (error) => {
      outcomes.push(error ? "error" : "success");
    });
    expect(pending).to.have.lengthOf(2);

    const sign = ({ signedInfo, key }: (typeof pending)[number]) =>
      crypto.createSign("RSA-SHA256").update(signedInfo).sign(key, "base64");

    pending[1].callback(null, sign(pending[1]));
    const signedSecond = signer.getSignedXml();
    expect(outcomes).to.deep.equal(["success"]);
    expect(signedSecond).to.contain('<value Id="_0">second</value>');

    pending[0].callback(null, sign(pending[0]));

    expect(outcomes).to.deep.equal(["success", "error"]);
    expect(signer.getSignedXml()).to.equal(signedSecond);
    expect(signer.getSignedXml()).not.to.contain("first");
    expect(signatureCount(signer.getSignedXml())).to.equal(1);
  });

  it("does not publish a late async verification into a newer generation", async function () {
    let resolveVerification: ((isValid: boolean) => void) | undefined;

    class DeferredVerificationRsaSha256 implements SignatureAlgorithm {
      getAlgorithmName = () => RSA_SHA256;

      getSignature(signedInfo: crypto.BinaryLike, key: crypto.KeyLike): string {
        return crypto.createSign("RSA-SHA256").update(signedInfo).sign(key, "base64");
      }

      verifySignature(): boolean {
        return true;
      }

      async verifySignatureAsync(): Promise<boolean> {
        return new Promise((resolve) => {
          resolveVerification = resolve;
        });
      }
    }

    const firstSigner = createSigner();
    firstSigner.computeSignature("<root><value>verified</value></root>");
    const signedFirst = firstSigner.getSignedXml();

    const signer = createSigner(DeferredVerificationRsaSha256);
    signer.loadSignature(firstSigner.getSignatureXml());
    const pendingVerification = signer.checkSignatureAsync(signedFirst);
    expect(signer.getSignedReferences()).to.be.empty;

    signer.loadSignature(firstSigner.getSignatureXml());
    expect(signer.checkSignature(signedFirst)).to.be.true;
    expect(signer.getSignedReferences()).to.have.lengthOf(1);

    resolveVerification?.(true);
    expect(await pendingVerification).to.be.true;

    expect(signer.getSignedReferences()).to.have.lengthOf(1);
    /* eslint-disable-next-line deprecation/deprecation */
    expect(signer.getReferences().map((reference) => reference.signedReference)).to.not.include(
      undefined,
    );
  });
});
