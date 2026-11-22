import { SignedXml, type SignatureAlgorithm } from "../src/index";
import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as isDomNode from "@xmldom/is-dom-node";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import { expect } from "chai";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

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
    digestAlgorithm: SHA256,
    transforms: [ENVELOPED, EXCLUSIVE_C14N],
  });
  sig.computeSignature(body);
  return { xml: sig.getSignedXml(), signatureXml: sig.getSignatureXml() };
}

function embeddedCertificate(signatureXml: string): string {
  const certificate = xpath.select1(
    "//*[local-name(.)='X509Certificate']",
    new xmldom.DOMParser().parseFromString(signatureXml),
  );
  isDomNode.assertIsElementNode(certificate);
  return (certificate.textContent ?? "").replace(/\s+/g, "");
}

function verifierUsingKeyInfo(gates: Array<() => void>): SignedXml {
  class GatedRsaSha256 implements SignatureAlgorithm {
    getAlgorithmName = () => RSA_SHA256;

    getSignature(): never {
      throw new Error("this algorithm verifies only asynchronously");
    }

    verifySignature(): never {
      throw new Error("this algorithm verifies only asynchronously");
    }

    async verifySignatureAsync(
      material: string,
      key: crypto.KeyLike,
      signatureValue: string,
    ): Promise<boolean> {
      await new Promise<void>((resolve) => gates.push(resolve));
      return crypto
        .createVerify("RSA-SHA256")
        .update(material)
        .verify(key, signatureValue, "base64");
    }
  }

  const verifier = new SignedXml({ getCertFromKeyInfo: SignedXml.getCertFromKeyInfo });
  verifier.SignatureAlgorithms[RSA_SHA256] = GatedRsaSha256;
  return verifier;
}

describe("KeyInfo rotation", function () {
  const oldDocument = signWith(oldIdentity, "<root><a>old-signer</a></root>");
  const rotatedDocument = signWith(rotatedIdentity, "<root><a>rotated-signer</a></root>");

  it("rejects a late verification whose KeyInfo was replaced by a retry", async function () {
    expect(embeddedCertificate(oldDocument.signatureXml)).to.not.equal(
      embeddedCertificate(rotatedDocument.signatureXml),
    );

    const gates: Array<() => void> = [];
    const verifier = verifierUsingKeyInfo(gates);

    verifier.loadSignature(oldDocument.signatureXml);
    const oldCheck = verifier.checkSignatureAsync(oldDocument.xml);

    verifier.loadSignature(rotatedDocument.signatureXml);
    const retry = verifier.checkSignatureAsync(rotatedDocument.xml);
    expect(gates).to.have.lengthOf(2);

    gates[1]();
    expect(await retry).to.be.true;
    expect(verifier.getSignedReferences()).to.have.lengthOf(1);
    expect(verifier.getSignedReferences()[0]).to.contain("rotated-signer");

    gates[0]();
    await assert.rejects(oldCheck, { message: /changed before verification completed/ });

    expect(verifier.getSignedReferences()).to.have.lengthOf(1);
    expect(verifier.getSignedReferences()[0]).to.contain("rotated-signer");
  });

  it("rejects a success after the loaded KeyInfo changed", async function () {
    const gates: Array<() => void> = [];
    const verifier = verifierUsingKeyInfo(gates);
    const document = new xmldom.DOMParser().parseFromString(oldDocument.signatureXml);
    const signature = xpath.select1("//*[local-name(.)='Signature']", document);
    isDomNode.assertIsNodeLike(signature);
    verifier.loadSignature(signature);

    const certificate = xpath.select1("//*[local-name(.)='X509Certificate']", signature);
    isDomNode.assertIsElementNode(certificate);
    certificate.textContent = embeddedCertificate(rotatedDocument.signatureXml);

    const check = verifier.checkSignatureAsync(oldDocument.xml);
    expect(gates).to.have.lengthOf(1);
    gates[0]();

    await assert.rejects(check, { message: /changed before verification completed/ });
    expect(verifier.getSignedReferences()).to.be.empty;
  });

  it("lets a late check with the same certificate finish without publishing it", async function () {
    const sameIdentity = signWith(oldIdentity, "<root><a>another-old-signer</a></root>");
    const gates: Array<() => void> = [];
    const verifier = verifierUsingKeyInfo(gates);

    verifier.loadSignature(oldDocument.signatureXml);
    const oldCheck = verifier.checkSignatureAsync(oldDocument.xml);

    verifier.loadSignature(sameIdentity.signatureXml);
    const retry = verifier.checkSignatureAsync(sameIdentity.xml);
    expect(gates).to.have.lengthOf(2);

    gates[1]();
    expect(await retry).to.be.true;
    expect(verifier.getSignedReferences()[0]).to.contain("another-old-signer");

    gates[0]();
    expect(await oldCheck).to.be.true;
    expect(verifier.getSignedReferences()).to.have.lengthOf(1);
    expect(verifier.getSignedReferences()[0]).to.contain("another-old-signer");
  });

  it("does not reuse KeyInfo after loading another signature fails", function () {
    const verifier = new SignedXml({ getCertFromKeyInfo: SignedXml.getCertFromKeyInfo });
    verifier.loadSignature(oldDocument.signatureXml);

    const broken = oldDocument.signatureXml.replace(/<DigestValue>[^<]*<\/DigestValue>/, "");
    expect(() => verifier.loadSignature(broken)).to.throw(/could not find DigestValue node/);

    expect(() => verifier.checkSignature(oldDocument.xml)).to.throw("No signature found.");
  });

  it("still verifies with the first certificate in a multi-certificate KeyInfo", function () {
    const bundle = fs.readFileSync("./test/static/client_bundle.pem");
    const signer = new SignedXml({
      privateKey: bundle,
      publicCert: bundle,
      canonicalizationAlgorithm: EXCLUSIVE_C14N,
      signatureAlgorithm: RSA_SHA256,
    });
    signer.addReference({
      xpath: "/*",
      digestAlgorithm: SHA256,
      transforms: [ENVELOPED, EXCLUSIVE_C14N],
    });
    signer.computeSignature("<root><x>trusted</x></root>");

    const signedXml = signer.getSignedXml();
    const signature = xpath.select1(
      "//*[local-name(.)='Signature']",
      new xmldom.DOMParser().parseFromString(signedXml),
    );
    isDomNode.assertIsNodeLike(signature);

    const verifier = new SignedXml({ getCertFromKeyInfo: SignedXml.getCertFromKeyInfo });
    verifier.loadSignature(signature);

    expect(verifier.checkSignature(signedXml)).to.be.true;
  });
});
