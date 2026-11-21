import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { ExclusiveCanonicalization, SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

function verify(xml: string): boolean {
  const verifier = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  const doc = new xmldom.DOMParser().parseFromString(xml);
  verifier.loadSignature(verifier.findSignatures(doc)[0]);
  return verifier.checkSignature(xml);
}

function signWithPrefixList(xml: string, prefixList: string[]): string {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: rsaSha256,
  });
  signer.addReference({
    xpath: "//*[local-name(.)='item']",
    transforms: [exclusiveC14n],
    digestAlgorithm: sha256,
    inclusiveNamespacesPrefixList: prefixList,
  });
  signer.computeSignature(xml);
  return signer.getSignedXml();
}

describe("exclusive canonicalization PrefixList integrity", function () {
  it("rejects a namespace declaration impersonated by an ordinary prefixed attribute", function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [exclusiveC14n],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      inclusiveNamespacesPrefixList: ["bar"],
    });
    signer.computeSignature(
      '<root><item xmlns:foo="urn:foo" foo:bar="urn:value" type="bar:Admin"/></root>',
    );

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace(
      'type="bar:Admin"',
      'xmlns:bar="urn:value" type="bar:Admin"',
    );
    expect(tamperedXml).not.to.equal(signedXml);
    expect(verify(tamperedXml)).to.be.false;
  });

  it("keeps a prefix context out of the document it canonicalizes", function () {
    const doc = new xmldom.DOMParser().parseFromString(
      '<root xmlns:p="urn:one"><item>value</item></root>',
    );
    const item = doc.getElementsByTagName("item")[0];
    const before = doc.toString();

    const canonical = new ExclusiveCanonicalization().process(item, {
      ancestorNamespaces: [{ prefix: "p", namespaceURI: "urn:one" }],
      inclusiveNamespacesPrefixList: ["p"],
    });

    expect(canonical).to.equal('<item xmlns:p="urn:one">value</item>');
    expect(doc.toString()).to.equal(before);
  });

  it("canonicalizes documents with the same prefix in different namespaces independently", function () {
    const first = new xmldom.DOMParser().parseFromString(
      '<root xmlns:p="urn:one"><item>first</item></root>',
    );
    const second = new xmldom.DOMParser().parseFromString(
      '<root xmlns:p="urn:two"><item>second</item></root>',
    );
    const canonicalization = new ExclusiveCanonicalization();
    const canonicalize = (doc: Document, namespaceURI: string) =>
      canonicalization.process(doc.getElementsByTagName("item")[0], {
        ancestorNamespaces: [{ prefix: "p", namespaceURI }],
        inclusiveNamespacesPrefixList: ["p"],
      });

    expect(canonicalize(first, "urn:one")).to.equal('<item xmlns:p="urn:one">first</item>');
    expect(canonicalize(second, "urn:two")).to.equal('<item xmlns:p="urn:two">second</item>');
  });

  it("verifies each document with its PrefixList when a verifier is reused", function () {
    const first = signWithPrefixList('<root xmlns:p="urn:one"><item>first</item></root>', ["p"]);
    const second = signWithPrefixList('<root xmlns:p="urn:two"><item>second</item></root>', ["p"]);
    const verifier = new SignedXml({
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });

    for (const xml of [first, second, first]) {
      const doc = new xmldom.DOMParser().parseFromString(xml);
      verifier.loadSignature(verifier.findSignatures(doc)[0]);
      expect(verifier.checkSignature(xml)).to.be.true;
    }
  });

  it("verifies documents with the same prefix concurrently", async function () {
    const documents = [
      signWithPrefixList('<root xmlns:p="urn:one"><item>first</item></root>', ["p"]),
      signWithPrefixList('<root xmlns:p="urn:two"><item>second</item></root>', ["p"]),
    ];

    const results = await Promise.all(
      documents.map((xml) => {
        const verifier = new SignedXml({
          publicCert: fs.readFileSync("./test/static/client_public.pem"),
        });
        const doc = new xmldom.DOMParser().parseFromString(xml);
        verifier.loadSignature(verifier.findSignatures(doc)[0]);
        return verifier.checkSignatureAsync(xml);
      }),
    );

    expect(results).to.deep.equal([true, true]);
  });

  it("verifies a signature after attribute order changes", function () {
    const signedXml = signWithPrefixList(
      '<root xmlns:p="urn:one"><item b="2" a="1">value</item></root>',
      ["p"],
    );
    expect(verify(signedXml)).to.be.true;

    const reorderedXml = signedXml.replace('b="2" a="1"', 'a="1" b="2"');
    expect(reorderedXml).not.to.equal(signedXml);
    expect(verify(reorderedXml)).to.be.true;
  });
});
