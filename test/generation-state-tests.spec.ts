import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as crypto from "crypto";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml, type SignatureAlgorithm } from "../src/index";

describe("Document generation state", function () {
  const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const rsaSha256 = "http://www.w3.org/2001/04/xmlenc#rsa-sha256";
  const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
  const privateKey = fs.readFileSync("./test/static/client.pem");
  const publicCert = fs.readFileSync("./test/static/client_public.pem");

  function sign(xml: string, ids: string[]): string {
    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    for (const id of ids) {
      sig.addReference({
        xpath: `//*[@Id='${id}']`,
        transforms: [exclusiveC14n],
        digestAlgorithm: sha256,
      });
    }
    sig.computeSignature(xml);
    return sig.getSignedXml();
  }

  function loadSignature(sig: SignedXml, signedXml: string): SignedXml {
    const signature = xpath.select1(
      "//*[local-name(.)='Signature']",
      new xmldom.DOMParser().parseFromString(signedXml),
    );
    isDomNode.assertIsNodeLike(signature);
    sig.loadSignature(signature);
    return sig;
  }

  const signedOne = sign("<root><data Id='_0'>trusted</data></root>", ["_0"]);

  it("freezes the reference set when a signature is loaded", function () {
    const sig = new SignedXml({ publicCert });
    loadSignature(sig, signedOne);

    const loaded = sig.getReferences();
    expect(loaded).to.have.lengthOf(1);
    expect(loaded[0].uri).to.equal("#_0");

    loadSignature(sig, signedOne);
    expect(sig.getReferences()).to.have.lengthOf(1);
    expect(sig.getReferences()).to.not.include(loaded[0]);
    expect(sig.getReferences()[0].uri).to.equal("#_0");
    expect(sig.getSignedReferences()).to.be.empty;
  });

  it("does not let a tampered document reuse digest caches from an earlier check", function () {
    const sig = new SignedXml({ publicCert });
    loadSignature(sig, signedOne);

    expect(sig.checkSignature(signedOne)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);

    const tampered = signedOne.replace("trusted", "tampered");
    expect(sig.checkSignature(tampered)).to.be.false;

    expect(sig.getSignedReferences()).to.be.empty;
    /* eslint-disable-next-line deprecation/deprecation */
    expect(sig.getReferences().map((ref) => ref.signedReference)).to.deep.equal([undefined]);
  });

  it("publishes only the references of the document the current generation checked", function () {
    const other = sign("<root><data Id='_0'>other</data></root>", ["_0"]);
    const sig = new SignedXml({ publicCert });
    loadSignature(sig, signedOne);

    expect(sig.checkSignature(signedOne)).to.be.true;
    const firstReferences = sig.getSignedReferences();
    expect(firstReferences).to.have.lengthOf(1);

    expect(sig.checkSignature(other)).to.be.true;
    const secondReferences = sig.getSignedReferences();
    expect(secondReferences).to.have.lengthOf(1);
    expect(secondReferences[0]).to.contain("other");
    expect(secondReferences[0]).to.not.equal(firstReferences[0]);
  });

  it("keeps every reference when a document carries more than one", function () {
    const multi = sign(
      "<root><assertion Id='_0'>signed</assertion><extensions Id='_1'/></root>",
      ["_0", "_1"],
    );
    const sig = new SignedXml({ publicCert });
    loadSignature(sig, multi);

    expect(sig.getReferences().map((ref) => ref.uri)).to.deep.equal(["#_0", "#_1"]);
    expect(sig.checkSignature(multi)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(2);

    const tampered = multi.replace("signed", "tampered");
    expect(sig.checkSignature(tampered)).to.be.false;
    expect(sig.getSignedReferences()).to.be.empty;

    expect(sig.checkSignature(multi)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(2);
  });

  it("accepts repeated verification of the same document on one instance", function () {
    const sig = new SignedXml({ publicCert });
    loadSignature(sig, signedOne);

    expect(sig.checkSignature(signedOne)).to.be.true;
    expect(sig.checkSignature(signedOne)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);
  });

  it("does not confuse documents that use the same ID", function () {
    const first = sign("<root><data Id='shared'>first</data></root>", ["shared"]);
    const second = sign("<root><data Id='shared'>second</data></root>", ["shared"]);
    const sig = new SignedXml({ publicCert });

    loadSignature(sig, first);
    expect(sig.checkSignature(first)).to.be.true;
    expect(sig.getSignedReferences()[0]).to.contain("first");

    loadSignature(sig, second);
    expect(sig.checkSignature(second)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);
    expect(sig.getSignedReferences()[0]).to.contain("second");

    expect(sig.checkSignature(first)).to.be.false;
    expect(sig.getSignedReferences()).to.be.empty;
  });

  it("does not publish a late asynchronous answer into a newer generation", async function () {
    let answer: (isValid: boolean) => void = () => {};
    class DeferredRsaSha256 implements SignatureAlgorithm {
      getAlgorithmName = () => rsaSha256;

      getSignature(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string {
        return crypto.createSign("RSA-SHA256").update(signedInfo).sign(privateKey, "base64");
      }

      verifySignature(): boolean {
        return true;
      }

      async verifySignatureAsync(): Promise<boolean> {
        return new Promise((resolve) => {
          answer = resolve;
        });
      }
    }

    const sig = new SignedXml({ publicCert });
    sig.SignatureAlgorithms[rsaSha256] = DeferredRsaSha256;
    loadSignature(sig, signedOne);

    const pending = sig.checkSignatureAsync(signedOne);
    expect(sig.getSignedReferences()).to.be.empty;

    // A second document takes over the instance before the first algorithm answers.
    loadSignature(sig, signedOne);
    expect(sig.checkSignature(signedOne)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(1);

    answer(true);
    await pending;

    expect(sig.getSignedReferences()).to.have.lengthOf(1);
    /* eslint-disable-next-line deprecation/deprecation */
    expect(sig.getReferences().map((ref) => ref.signedReference)).to.not.include(undefined);
  });
});
