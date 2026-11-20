import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";
import * as crypto from "crypto";
import { SignedXml } from "../src/index";

describe("Reference dereference hardening", function () {
  const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
  const enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
  const privateKey = fs.readFileSync("./test/static/client.pem");
  const publicCert = fs.readFileSync("./test/static/client_public.pem");

  function loadSignature(sig: SignedXml, xml: string): SignedXml {
    const signature = xpath.select1(
      "//*[local-name(.)='Signature']",
      new xmldom.DOMParser().parseFromString(xml),
    );
    isDomNode.assertIsNodeLike(signature);
    sig.loadSignature(signature);
    return sig;
  }

  function signFragment(): string {
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='assertion']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature('<response><assertion Id="_0">trusted</assertion></response>');
    return signer.getSignedXml();
  }

  it("rejects a shadow node that repeats the referenced id on a second element", function () {
    const xml = signFragment().replace(
      "</response>",
      '<assertion Id="_0">forged shadow</assertion></response>',
    );
    const sig = loadSignature(new SignedXml({ publicCert }), xml);

    expect(() => sig.checkSignature(xml)).to.throw(/in order to prevent signature wrapping attack/);
    expect(sig.getSignedReferences()).to.be.empty;
  });

  it("rejects a shadow node that repeats the id under a different recognized attribute", function () {
    const xml = signFragment().replace(
      "</response>",
      '<assertion id="_0">forged shadow</assertion></response>',
    );
    const sig = loadSignature(new SignedXml({ publicCert }), xml);

    expect(() => sig.checkSignature(xml)).to.throw(/in order to prevent signature wrapping attack/);
    expect(sig.getSignedReferences()).to.be.empty;
  });

  it("accepts one element that carries the same id on two recognized attributes", function () {
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='assertion']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature('<response><assertion Id="_0" ID="_0">trusted</assertion></response>');
    const xml = signer.getSignedXml();
    const sig = loadSignature(new SignedXml({ publicCert }), xml);

    expect(sig.checkSignature(xml)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);
  });

  // A document that is never passed through the signing API can still load a Reference whose
  // fragment dereferences the Signature element itself.
  function selfReferencingDocument(target: "Signature" | "SignedInfo"): string {
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "/*",
      transforms: [enveloped, exclusiveC14n],
      digestAlgorithm: sha256,
      isEmptyUri: true,
    });
    signer.computeSignature("<root><data>trusted</data></root>", {
      location: { reference: "//*[local-name(.)='root']", action: "append" },
    });

    const doc = new xmldom.DOMParser().parseFromString(signer.getSignedXml());
    const targetElem = xpath.select1(`//*[local-name(.)='${target}']`, doc) as Element;
    targetElem.setAttribute("Id", "self");
    const signedInfo = xpath.select1("//*[local-name(.)='SignedInfo']", doc) as Element;
    const reference = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
    reference.setAttribute("URI", "#self");
    const transforms = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Transforms");
    const transform = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Transform");
    transform.setAttribute("Algorithm", exclusiveC14n);
    transforms.appendChild(transform);
    const digestMethod = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "DigestMethod");
    digestMethod.setAttribute("Algorithm", sha256);
    const digestValue = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "DigestValue");
    digestValue.textContent = "placeholder";
    reference.appendChild(transforms);
    reference.appendChild(digestMethod);
    reference.appendChild(digestValue);
    signedInfo.appendChild(reference);

    const signedInfoCanon = new SignedXml({
      canonicalizationAlgorithm: exclusiveC14n,
    }).getCanonXml([exclusiveC14n], signedInfo, { ancestorNamespaces: [] });
    const signatureValue = crypto
      .createSign("RSA-SHA256")
      .update(signedInfoCanon)
      .sign(privateKey, "base64");
    (xpath.select1("//*[local-name(.)='SignatureValue']", doc) as Element).textContent =
      signatureValue;

    return doc.toString();
  }

  for (const target of ["Signature", "SignedInfo"] as const) {
    it(`rejects a Reference whose fragment points at the ${target} element`, function () {
      const xml = selfReferencingDocument(target);
      const sig = loadSignature(new SignedXml({ publicCert }), xml);

      expect(() => sig.checkSignature(xml)).to.throw(
        /Cannot validate a reference to the Signature or SignedInfo element itself/,
      );
      expect(sig.getSignedReferences()).to.be.empty;
    });
  }

  it("validates a document that mixes an empty URI with a fragment reference", function () {
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "/*",
      transforms: [enveloped, exclusiveC14n],
      digestAlgorithm: sha256,
      isEmptyUri: true,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='data']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature('<root><data Id="_0">payload</data></root>', {
      location: { reference: "//*[local-name(.)='root']", action: "append" },
    });
    const xml = signer.getSignedXml();
    const sig = loadSignature(new SignedXml({ publicCert }), xml);

    expect(sig.checkSignature(xml)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(2);
  });

  it("keeps validating wsu:Id references", function () {
    const signer = new SignedXml({
      privateKey,
      idMode: "wssecurity",
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='data']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature("<root><data>secured</data></root>", {
      location: { reference: "//*[local-name(.)='root']", action: "append" },
    });
    const xml = signer.getSignedXml();
    const sig = loadSignature(new SignedXml({ publicCert, idMode: "wssecurity" }), xml);

    expect(sig.checkSignature(xml)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);
  });
});
