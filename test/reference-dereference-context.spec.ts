import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const inclusiveC14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

function sign(xml: string, transform: string, xpath: string, existingPrefixes = {}) {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: rsaSha256,
  });
  signer.addReference({ xpath, transforms: [transform], digestAlgorithm: sha256 });
  signer.computeSignature(xml, { existingPrefixes });
  return signer;
}

function loadVerifier(xml: string, namespaceResolver?: XPathNSResolver) {
  const verifier = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  if (namespaceResolver) {
    verifier.namespaceResolver = namespaceResolver;
  }
  const doc = new xmldom.DOMParser().parseFromString(xml);
  verifier.loadSignature(verifier.findSignatures(doc)[0]);
  return verifier;
}

describe("reference canonicalization uses the dereferenced node's namespace context", function () {
  it("hoists an ancestor default namespace under inclusive C14N regardless of a namespace resolver", function () {
    const xml =
      '<root xmlns="urn:trusted" xmlns:other="urn:other-ns">' +
      "<wrapper>" +
      '<p:item xmlns:p="urn:item">value</p:item>' +
      "</wrapper></root>";
    const signedXml = sign(xml, inclusiveC14n, "//p:item", { p: "urn:item" }).getSignedXml();

    let resolverCalls = 0;
    const throwingResolver: XPathNSResolver = {
      lookupNamespaceURI() {
        resolverCalls++;
        throw new Error("Not implemented");
      },
    };

    expect(loadVerifier(signedXml, throwingResolver).checkSignature(signedXml)).to.be.true;
    expect(resolverCalls).to.equal(0);
    expect(loadVerifier(signedXml, { lookupNamespaceURI: () => null }).checkSignature(signedXml)).to
      .be.true;
    expect(loadVerifier(signedXml).checkSignature(signedXml)).to.be.true;

    const verifier = loadVerifier(signedXml);
    verifier.checkSignature(signedXml);
    expect(verifier.getSignedReferences()[0]).to.contain('xmlns="urn:trusted"');
    expect(verifier.getSignedReferences()[0]).to.contain('xmlns:other="urn:other-ns"');
  });

  it("canonicalizes the same bytes on the signing and verification sides", function () {
    const xml =
      '<root xmlns="urn:trusted"><wrapper xmlns:inter="urn:inter-ns">' +
      '<p:item xmlns:p="urn:item">value</p:item></wrapper></root>';
    const signer = sign(xml, inclusiveC14n, "//p:item", { p: "urn:item" });
    const signedXml = signer.getSignedXml();

    const verifier = loadVerifier(signedXml);
    expect(verifier.checkSignature(signedXml)).to.be.true;
    expect(verifier.getSignedReferences()).to.deep.equal([
      '<p:item xmlns="urn:trusted" xmlns:inter="urn:inter-ns" xmlns:p="urn:item" Id="_0">value</p:item>',
    ]);
  });

  it("is not diverted by a namespace resolver that maps the reference prefix elsewhere", function () {
    const xml = '<root xmlns="urn:trusted"><p:item xmlns:p="urn:item">value</p:item></root>';
    const signedXml = sign(xml, inclusiveC14n, "//p:item", { p: "urn:item" }).getSignedXml();

    let resolverCalls = 0;
    const evilResolver: XPathNSResolver = {
      lookupNamespaceURI: (prefix) => {
        resolverCalls++;
        return prefix === "p" ? "urn:attacker" : null;
      },
    };
    expect(loadVerifier(signedXml, evilResolver).checkSignature(signedXml)).to.be.true;
    expect(resolverCalls).to.equal(0);
  });

  it("stably rejects two elements that share the referenced ID value", function () {
    const signedXml = sign(
      "<root><a Id='_same'>one</a><b>two</b></root>",
      exclusiveC14n,
      "//*[local-name(.)='a']",
    ).getSignedXml();
    const wrapped = signedXml.replace("<b>two</b>", "<b Id='_same'>two</b>");

    expect(() => loadVerifier(wrapped).checkSignature(wrapped)).to.throw(
      /multiple elements with the same value/,
    );
  });

  it("accepts a single element that carries the referenced value on two ID attributes", function () {
    const signedXml = sign(
      '<root><item Id="_x" ID="_x">one</item></root>',
      exclusiveC14n,
      "//*[local-name(.)='item']",
    ).getSignedXml();

    expect(loadVerifier(signedXml).checkSignature(signedXml)).to.be.true;
  });

  it("does not treat different ID attribute values on one element as a duplicate ID", function () {
    const signedXml = sign(
      '<root><item Id="_x">one</item></root>',
      exclusiveC14n,
      "//*[local-name(.)='item']",
    ).getSignedXml();
    const withOtherId = signedXml.replace('<item Id="_x">', '<item Id="_x" ID="_y">');

    expect(() => loadVerifier(withOtherId).checkSignature(withOtherId)).not.to.throw(
      /multiple elements with the same value/,
    );
  });
});
