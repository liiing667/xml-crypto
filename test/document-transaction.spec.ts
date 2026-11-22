import { SignedXml, type SignatureAlgorithm } from "../src/index";
import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import { expect } from "chai";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

const privateKey = fs.readFileSync("./test/static/client.pem");
const publicCert = fs.readFileSync("./test/static/client_public.pem");

// Holds each asynchronous verdict back until the test releases it, so two checks sharing one
// instance can be interleaved in any order.
class VerdictGate {
  private resolvers: Array<() => void> = [];

  hold(verdict: boolean): Promise<boolean> {
    return new Promise((resolve) => {
      this.resolvers.push(() => resolve(verdict));
    });
  }

  get waiting(): number {
    return this.resolvers.length;
  }

  answerOldest(): void {
    this.answer(this.resolvers.shift());
  }

  answerNewest(): void {
    this.answer(this.resolvers.pop());
  }

  private answer(resolver: (() => void) | undefined): void {
    if (resolver == null) {
      throw new Error("no verdict is waiting");
    }
    resolver();
  }
}

// RSA-SHA256 through Node's crypto, with `verifySignatureAsync()` answering through the gate.
function gatedRsaSha256(gate: VerdictGate): new () => SignatureAlgorithm {
  return class implements SignatureAlgorithm {
    getAlgorithmName = () => RSA_SHA256;

    getSignature(signedInfo: crypto.BinaryLike, key: crypto.KeyLike): string {
      return crypto.createSign("RSA-SHA256").update(signedInfo).sign(key, "base64");
    }

    verifySignature(material: string, key: crypto.KeyLike, signatureValue: string): boolean {
      return crypto
        .createVerify("RSA-SHA256")
        .update(material)
        .verify(key, signatureValue, "base64");
    }

    verifySignatureAsync(
      material: string,
      key: crypto.KeyLike,
      signatureValue: string,
    ): Promise<boolean> {
      return gate.hold(this.verifySignature(material, key, signatureValue));
    }
  };
}

function sign(
  xml: string,
  options: { prefix?: string } = {},
): { signedXml: string; signatureXml: string } {
  const sig = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: EXCLUSIVE_C14N,
    signatureAlgorithm: RSA_SHA256,
  });
  sig.addReference({
    xpath: "/*",
    digestAlgorithm: SHA256,
    transforms: [ENVELOPED, EXCLUSIVE_C14N],
  });
  sig.computeSignature(xml, options);
  return { signedXml: sig.getSignedXml(), signatureXml: sig.getSignatureXml() };
}

function createVerifier(algorithm?: new () => SignatureAlgorithm): SignedXml {
  const sig = new SignedXml({ publicCert });
  if (algorithm) {
    sig.SignatureAlgorithms[RSA_SHA256] = algorithm;
  }
  return sig;
}

const signatureValueOf = (signatureXml: string) =>
  signatureXml.match(/<SignatureValue>([^<]*)<\/SignatureValue>/)?.[1];

// The references still match their digests; only the signature over SignedInfo does not verify.
const withAnotherSignatureValue = (signed: string) =>
  signed.replace(
    /(<SignatureValue>)(.)/,
    (match, open: string, first: string) => open + (first === "A" ? "B" : "A"),
  );

describe("Document transaction", function () {
  const docA = sign("<root><a>alpha</a></root>");
  const docB = sign("<root><a>beta</a></root>");
  const contentA = '<root Id="_0"><a>alpha</a></root>';
  const contentB = '<root Id="_0"><a>beta</a></root>';

  it("publishes nothing for a check a newer check superseded before its verdict arrived", async function () {
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    sig.loadSignature(docA.signatureXml);
    const first = sig.checkSignatureAsync(docA.signedXml);
    sig.loadSignature(docB.signatureXml);
    const second = sig.checkSignatureAsync(docB.signedXml);
    expect(gate.waiting).to.equal(2);

    gate.answerOldest();
    expect(await first).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([]);

    gate.answerNewest();
    expect(await second).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentB]);
  });

  it("does not let a late verdict replace what a newer check published", async function () {
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    sig.loadSignature(docA.signatureXml);
    const first = sig.checkSignatureAsync(docA.signedXml);
    sig.loadSignature(docB.signatureXml);
    const second = sig.checkSignatureAsync(docB.signedXml);

    gate.answerNewest();
    expect(await second).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentB]);

    gate.answerOldest();
    expect(await first).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentB]);
    /* eslint-disable-next-line deprecation/deprecation */
    expect(sig.getReferences().map((ref) => ref.signedReference)).to.deep.equal([contentB]);
  });

  it("ignores the verdict of a check the caller retried while it was in flight", async function () {
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    sig.loadSignature(docA.signatureXml);
    const abandoned = sig.checkSignatureAsync(docA.signedXml);
    sig.loadSignature(docA.signatureXml);
    const retried = sig.checkSignatureAsync(docA.signedXml);

    gate.answerOldest();
    expect(await abandoned).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([]);

    gate.answerOldest();
    expect(await retried).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentA]);
  });

  it("does not let a late rejection clear what a newer check published", async function () {
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    sig.loadSignature(withAnotherSignatureValue(docA.signatureXml));
    const first = sig.checkSignatureAsync(withAnotherSignatureValue(docA.signedXml));

    sig.loadSignature(docB.signatureXml);
    expect(sig.checkSignature(docB.signedXml)).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentB]);

    gate.answerOldest();
    await assert.rejects(first, { message: /^invalid signature: / });
    expect(sig.getSignedReferences()).to.deep.equal([contentB]);
  });

  it("rejects with the signature value of its own document, not a newer load's", async function () {
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    const tamperedSignatureXml = withAnotherSignatureValue(docA.signatureXml);
    sig.loadSignature(tamperedSignatureXml);
    const first = sig.checkSignatureAsync(withAnotherSignatureValue(docA.signedXml));

    sig.loadSignature(docB.signatureXml);

    gate.answerOldest();
    const signatureValue = signatureValueOf(tamperedSignatureXml);
    await assert.rejects(first, {
      message: `invalid signature: the signature value ${signatureValue} is incorrect`,
    });
  });

  it("keeps what each successful sequential check published, as checks before it did", function () {
    const sig = createVerifier();

    sig.loadSignature(docA.signatureXml);
    expect(sig.checkSignature(docA.signedXml)).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentA]);

    sig.loadSignature(docB.signatureXml);
    expect(sig.checkSignature(docB.signedXml)).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentA, contentB]);
  });

  it("adds what an asynchronous check authenticates to what earlier checks published", async function () {
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    sig.loadSignature(docA.signatureXml);
    expect(sig.checkSignature(docA.signedXml)).to.be.true;

    sig.loadSignature(docB.signatureXml);
    const second = sig.checkSignatureAsync(docB.signedXml);
    gate.answerOldest();
    expect(await second).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentA, contentB]);
  });

  it("publishes nothing for content that does not match its digest, even after an earlier success", async function () {
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    sig.loadSignature(docA.signatureXml);
    expect(sig.checkSignature(docA.signedXml)).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentA]);

    sig.loadSignature(docB.signatureXml);
    expect(await sig.checkSignatureAsync(docB.signedXml.replace("beta", "gamma"))).to.be.false;
    expect(sig.getSignedReferences()).to.deep.equal([]);
  });

  it("verifies a signature whose SignatureValue carries legal whitespace", function () {
    const withWhitespace = (xml: string) =>
      xml
        .replace("<SignatureValue>", "<SignatureValue>\n  ")
        .replace("</SignatureValue>", "\n</SignatureValue>");
    const sig = createVerifier();

    sig.loadSignature(withWhitespace(docA.signatureXml));
    expect(sig.checkSignature(withWhitespace(docA.signedXml))).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([contentA]);
  });

  it("verifies a prefixed signature through an asynchronous check", async function () {
    const prefixed = sign("<root><a>gamma</a></root>", { prefix: "ds" });
    const gate = new VerdictGate();
    const sig = createVerifier(gatedRsaSha256(gate));

    sig.loadSignature(prefixed.signatureXml);
    const check = sig.checkSignatureAsync(prefixed.signedXml);
    gate.answerOldest();

    expect(await check).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal(['<root Id="_0"><a>gamma</a></root>']);
  });
});
