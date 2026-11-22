import { SignedXml, type SignatureAlgorithm } from "../src/index";
import * as isDomNode from "@xmldom/is-dom-node";
import * as crypto from "crypto";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import { expect } from "chai";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

const oldIdentity = {
  privateKey: fs.readFileSync("./test/static/client.pem"),
  publicCert: fs.readFileSync("./test/static/client_public.pem"),
};

const rotatedIdentity = {
  privateKey: fs.readFileSync("./test/static/rotated-client.pem"),
  publicCert: fs.readFileSync("./test/static/rotated-client_public.pem"),
};

function signWith(
  identity: { privateKey: crypto.KeyLike; publicCert: crypto.KeyLike },
  body: string,
): { xml: string; signatureXml: string } {
  const sig = new SignedXml({
    privateKey: identity.privateKey,
    publicCert: identity.publicCert,
    canonicalizationAlgorithm: EXCLUSIVE_C14N,
    signatureAlgorithm: RSA_SHA256,
  });
  sig.addReference({
    xpath: "/*",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", EXCLUSIVE_C14N],
  });
  sig.computeSignature(body);
  return { xml: sig.getSignedXml(), signatureXml: sig.getSignatureXml() };
}

function embeddedCertificate(signatureXml: string): string {
  const node = xpath.select1(
    "//*[local-name(.)='X509Certificate']",
    new xmldom.DOMParser().parseFromString(signatureXml),
  );
  if (!isDomNode.isElementNode(node)) {
    throw new Error("the test signature carries no X509Certificate");
  }
  return (node.textContent ?? "").replace(/\s+/g, "");
}

// Verify against the certificate the document's own KeyInfo carries, so each signer identity is
// accepted on its own key. The verdict is delivered when the test releases the gate.
class GatedRsaSha256 implements SignatureAlgorithm {
  getAlgorithmName = () => RSA_SHA256;

  private readonly gates: Array<() => void>;

  constructor(gates: Array<() => void>) {
    this.gates = gates;
  }

  getSignature(): never {
    throw new Error("this algorithm verifies only asynchronously");
  }

  verifySignature(): never {
    throw new Error("this algorithm verifies only asynchronously");
  }

  getSignatureAsync(): never {
    throw new Error("this algorithm verifies only asynchronously");
  }

  async verifySignatureAsync(
    material: string,
    key: crypto.KeyLike,
    signatureValue: string,
  ): Promise<boolean> {
    await new Promise<void>((resolve) => this.gates.push(resolve));
    return crypto
      .createVerify("RSA-SHA256")
      .update(material)
      .verify(key, signatureValue, "base64");
  }
}

// The deprecated callback form, with the same gating.
/* eslint-disable deprecation/deprecation */
class GatedCallbackRsaSha256 implements SignatureAlgorithm {
  getAlgorithmName = () => RSA_SHA256;

  private readonly gates: Array<() => void>;

  constructor(gates: Array<() => void>) {
    this.gates = gates;
  }

  getSignature(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string {
    return crypto.createSign("RSA-SHA256").update(signedInfo).sign(privateKey, "base64");
  }

  verifySignature(
    material: string,
    key: crypto.KeyLike,
    signatureValue: string,
    callback?: (error: Error | null, isValid?: boolean) => void,
  ): void {
    if (!callback) {
      throw new Error("this algorithm answers only through a callback");
    }
    this.gates.push(() => {
      const isValid = crypto
        .createVerify("RSA-SHA256")
        .update(material)
        .verify(key, signatureValue, "base64");
      callback(null, isValid);
    });
  }
}
/* eslint-enable deprecation/deprecation */

function verifierTrustingKeyInfo(
  algorithm: new (gates: Array<() => void>) => SignatureAlgorithm,
  gates: Array<() => void>,
): SignedXml {
  const verifier = new SignedXml({
    getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
  });
  verifier.SignatureAlgorithms[RSA_SHA256] = class extends algorithm {
    constructor() {
      super(gates);
    }
  };
  return verifier;
}

describe("certificate rotation on one verifier instance", function () {
  // Distinct signed content lets the report name the identity that actually produced it.
  const oldDocument = signWith(oldIdentity, "<root><a>old-signer</a></root>");
  const rotatedDocument = signWith(rotatedIdentity, "<root><a>rotated-signer</a></root>");

  it(
    "publishes only the rotated signer when the earlier check answers after the retry",
    async function () {
      const oldCert = embeddedCertificate(oldDocument.signatureXml);
      const rotatedCert = embeddedCertificate(rotatedDocument.signatureXml);
      expect(oldCert).to.not.equal(rotatedCert);

      const gates: Array<() => void> = [];
      const verifier = verifierTrustingKeyInfo(GatedRsaSha256, gates);

      verifier.loadSignature(oldDocument.signatureXml);
      const firstCheck = verifier.checkSignatureAsync(oldDocument.xml);

      // The retry replaces KeyInfo, algorithms and the loaded references while the earlier
      // check is still waiting on its asynchronous verifier.
      verifier.loadSignature(rotatedDocument.signatureXml);
      const retry = verifier.checkSignatureAsync(rotatedDocument.xml);

      expect(gates).to.have.lengthOf(2);

      // The rotated check answers first, then the earlier, superseded check answers late.
      gates[1]();
      expect(await retry).to.be.true;
      expect(verifier.getSignedReferences()).to.have.lengthOf(1);
      expect(verifier.getSignedReferences()[0]).to.contain("rotated-signer");

      gates[0]();
      await firstCheck;

      // The late answer belongs to the old signer and must not replace the rotated identity as
      // the trusted one, nor add a second, untrusted entry to the report.
      expect(verifier.getSignedReferences()).to.have.lengthOf(1);
      expect(verifier.getSignedReferences()[0]).to.contain("rotated-signer");
      expect(verifier.getReferences().map((ref) => ref.signedReference)).to.deep.equal(
        verifier.getSignedReferences(),
      );
    },
  );

  it("keeps the same boundary through the deprecated callback form", function (done) {
    const gates: Array<() => void> = [];
    const verifier = verifierTrustingKeyInfo(GatedCallbackRsaSha256, gates);
    verifier.loadSignature(oldDocument.signatureXml);

    let settled = 0;
    /* eslint-disable-next-line deprecation/deprecation */
    verifier.checkSignature(oldDocument.xml, (firstError, firstValid) => {
      settled += 1;
      expect(firstError).to.equal(null);
      expect(firstValid).to.be.true;
      // Answering last, the superseded check must not have published over the rotated identity.
      expect(verifier.getSignedReferences()).to.have.lengthOf(1);
      expect(verifier.getSignedReferences()[0]).to.contain("rotated-signer");
      if (settled === 2) {
        done();
      }
    });

    verifier.loadSignature(rotatedDocument.signatureXml);
    /* eslint-disable-next-line deprecation/deprecation */
    verifier.checkSignature(rotatedDocument.xml, (retryError, retryValid) => {
      settled += 1;
      expect(retryError).to.equal(null);
      expect(retryValid).to.be.true;
      expect(verifier.getSignedReferences()).to.have.lengthOf(1);
      expect(verifier.getSignedReferences()[0]).to.contain("rotated-signer");
      if (settled === 2) {
        done();
      }
    });

    expect(gates).to.have.lengthOf(2);
    gates[1]();
    gates[0]();
  });
});
