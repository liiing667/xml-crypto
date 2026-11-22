import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const privateKey = fs.readFileSync("./test/static/client.pem");
const publicCert = fs.readFileSync("./test/static/client_public.pem");

function sign(xml: string): string {
  const sig = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: rsaSha256,
  });
  sig.addReference({
    xpath: "//*[local-name(.)='assertion']",
    transforms: [exclusiveC14n],
    digestAlgorithm: sha256,
  });
  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function loadSignature(xml: string): SignedXml {
  const sig = new SignedXml({ publicCert });
  const signature = xpath.select1(
    "//*[local-name(.)='Signature']",
    new xmldom.DOMParser().parseFromString(xml),
  );
  isDomNode.assertIsNodeLike(signature);
  sig.loadSignature(signature);
  return sig;
}

const entityDoctype = [
  '<!DOCTYPE response [<!ENTITY trusted "signed">',
  '<!ATTLIST assertion flag CDATA "default">]>',
].join(" ");

describe("Documents with a DOCTYPE", function () {
  const declarations: Array<[string, string]> = [
    ["an internal entity subset", entityDoctype],
    ["an external DTD", '<!DOCTYPE response SYSTEM "https://example.test/response.dtd">'],
  ];

  for (const [label, declaration] of declarations) {
    it(`checkSignature throws on ${label} before any reference is resolved`, function () {
      const signed = sign("<response><assertion>signed</assertion></response>");
      const withDoctype = signed.replace("<response>", `${declaration}<response>`);
      const sig = loadSignature(withDoctype);

      expect(() => sig.checkSignature(withDoctype)).to.throw(/document type declaration/);
      expect(sig.getSignedReferences()).to.be.empty;
      expect(
        sig.getReferences().every((reference) => reference.signedReference == null),
      ).to.be.true;
    });
  }

  it("checkSignatureAsync rejects before any reference is resolved", async function () {
    const signed = sign("<response><assertion>signed</assertion></response>");
    const withDoctype = signed.replace("<response>", `${entityDoctype}<response>`);
    const sig = loadSignature(withDoctype);

    let error: unknown;
    try {
      await sig.checkSignatureAsync(withDoctype);
    } catch (caught) {
      error = caught;
    }
    expect(error).to.be.instanceOf(Error);
    expect((error as Error).message).to.match(/document type declaration/);
    expect(sig.getSignedReferences()).to.be.empty;
  });

  it("computeSignature throws rather than signing unprocessed DTD semantics", function () {
    const xml = `${entityDoctype}<response><assertion>&trusted;</assertion></response>`;
    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    sig.addReference({
      xpath: "//*[local-name(.)='assertion']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });

    expect(() => sig.computeSignature(xml)).to.throw(/document type declaration/);
  });

  it("rejecting a DOCTYPE document hides the references of an earlier accepted one", function () {
    const signed = sign("<response><assertion>signed</assertion></response>");
    const sig = loadSignature(signed);
    expect(sig.checkSignature(signed)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);

    const withDoctype = signed.replace("<response>", `${entityDoctype}<response>`);
    expect(() => sig.checkSignature(withDoctype)).to.throw(/document type declaration/);

    expect(sig.getSignedReferences()).to.be.empty;
    expect(
      sig.getReferences().every((reference) => reference.signedReference == null),
    ).to.be.true;

    // The same instance still verifies the DOCTYPE-free document, so the rejection is not sticky.
    expect(sig.checkSignature(signed)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);
  });

  it("a failed reference check leaves nothing authenticated for a retry", function () {
    const signed = sign("<response><assertion>signed</assertion></response>");
    const tampered = signed.replace(">signed<", ">tampered<");
    const retry = loadSignature(tampered);

    expect(retry.checkSignature(tampered)).to.be.false;
    expect(retry.getSignedReferences()).to.be.empty;
    expect(
      retry.getReferences().every((reference) => reference.signedReference == null),
    ).to.be.true;

    // A retry of the unmodified document on the same instance authenticates the current bytes only.
    expect(retry.checkSignature(signed)).to.be.true;
    const authenticated = new xmldom.DOMParser().parseFromString(
      retry.getSignedReferences()[0],
    );
    expect(authenticated.documentElement?.textContent).to.equal("signed");
  });

  it("a failed retry on the same instance publishes nothing from the original", function () {
    const signed = sign("<response><assertion>signed</assertion></response>");
    const sig = loadSignature(signed);
    expect(sig.checkSignature(signed)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);

    const tampered = signed.replace(">signed<", ">tampered<");
    expect(sig.checkSignature(tampered)).to.be.false;

    // No data from the accepted document may remain visible through the failed attempt.
    expect(sig.getSignedReferences()).to.be.empty;
    expect(
      sig.getReferences().every((reference) => reference.signedReference == null),
    ).to.be.true;
  });

  it("still verifies a DOCTYPE-free document that uses namespaces", function () {
    const xml =
      '<response xmlns="urn:test" xmlns:p="urn:prefix">' +
      '<p:assertion attr="value">signed</p:assertion></response>';
    const signed = sign(xml);
    const sig = loadSignature(signed);

    expect(sig.checkSignature(signed)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);
    expect(sig.getSignedReferences()[0]).to.contain("xmlns:p=");
  });
});
