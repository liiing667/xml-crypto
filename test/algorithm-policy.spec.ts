import * as fs from "fs";
import * as crypto from "crypto";
import { expect } from "chai";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml } from "../src/index";
import { getKeyType } from "../src/utils";

describe("Algorithm policy", function () {
  const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const rsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
  const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
  const hmacSha1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

  const privateKey = fs.readFileSync("./test/static/client.pem");
  const publicCert = fs.readFileSync("./test/static/client_public.pem");
  const hmacKey = fs.readFileSync("./test/static/hmac.key");

  function sign(
    signatureAlgorithm: string,
    digestAlgorithm: string,
    key: crypto.KeyLike = privateKey,
  ): string {
    const sig = new SignedXml({
      privateKey: key as Buffer,
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm,
    });
    if (signatureAlgorithm === rsaSha1 || digestAlgorithm === sha1) {
      sig.enableWeakAlgorithms();
    }
    if (signatureAlgorithm === hmacSha1) {
      sig.enableHMAC();
    }
    sig.addReference({
      xpath: "//*[local-name(.)='book']",
      digestAlgorithm,
      transforms: [exclusiveC14n],
    });
    sig.computeSignature("<library><book>Harry Potter</book></library>");
    return sig.getSignedXml();
  }

  function loadSignature(
    xml: string,
    { weak = false, hmac = false }: { weak?: boolean; hmac?: boolean } = {},
  ): SignedXml {
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1("//*[local-name(.)='Signature']", doc);
    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    if (weak) {
      sig.enableWeakAlgorithms();
    }
    if (hmac) {
      sig.enableHMAC();
    }
    sig.loadSignature(node);
    return sig;
  }

  describe("weak algorithms are off by default", function () {
    it("refuses to sign with the rsa-sha1 signature algorithm", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: exclusiveC14n,
        signatureAlgorithm: rsaSha1,
      });
      sig.addReference({
        xpath: "//*[local-name(.)='book']",
        digestAlgorithm: sha256,
        transforms: [exclusiveC14n],
      });

      expect(() => sig.computeSignature("<library><book>Harry Potter</book></library>")).to.throw(
        /'http:\/\/www\.w3\.org\/2000\/09\/xmldsig#rsa-sha1' is disabled by default/,
      );
    });

    it("refuses to compute a sha1 digest", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: exclusiveC14n,
        signatureAlgorithm: rsaSha256,
      });
      sig.addReference({
        xpath: "//*[local-name(.)='book']",
        digestAlgorithm: sha1,
        transforms: [exclusiveC14n],
      });

      expect(() => sig.computeSignature("<library><book>Harry Potter</book></library>")).to.throw(
        /'http:\/\/www\.w3\.org\/2000\/09\/xmldsig#sha1' is disabled by default/,
      );
    });

    it("refuses to verify a legacy rsa-sha1 document without an explicit opt-in", function () {
      const xml = sign(rsaSha1, sha1);
      const freshVerifier = loadSignature(xml);
      freshVerifier.publicCert = publicCert;
      expect(() => freshVerifier.checkSignature(xml)).to.throw(/is disabled by default/);
      expect(freshVerifier.getSignedReferences()).to.be.empty;
    });

    it("still signs and verifies with the default strong algorithms", function () {
      const xml = sign(rsaSha256, sha256);
      const verifier = loadSignature(xml);
      verifier.publicCert = publicCert;

      expect(verifier.checkSignature(xml)).to.be.true;
      expect(verifier.getSignedReferences()).to.have.lengthOf(1);
    });
  });

  describe("enableWeakAlgorithms()", function () {
    it("lets a caller explicitly accept a legacy rsa-sha1 document", function () {
      const xml = sign(rsaSha1, sha1);
      const verifier = loadSignature(xml, { weak: true });
      verifier.enableWeakAlgorithms();
      verifier.publicCert = publicCert;

      expect(verifier.checkSignature(xml)).to.be.true;
      expect(verifier.getSignedReferences()).to.have.lengthOf(1);
    });
  });

  describe("key type matches the signature algorithm", function () {
    it("refuses to sign an HMAC signature with an asymmetric private key", function () {
      const sig = new SignedXml();
      sig.enableHMAC();
      sig.privateKey = privateKey;
      sig.signatureAlgorithm = hmacSha1;
      sig.canonicalizationAlgorithm = exclusiveC14n;
      sig.addReference({
        xpath: "//*[local-name(.)='book']",
        digestAlgorithm: sha1,
        transforms: [exclusiveC14n],
      });

      expect(() => sig.computeSignature("<library><book>Harry Potter</book></library>")).to.throw(
        /requires a secret key, but was given a asymmetric key/,
      );
    });

    it("refuses to verify an HMAC signature when handed an RSA public key", function () {
      const xml = sign(hmacSha1, sha1, hmacKey);
      const verifier = loadSignature(xml, { hmac: true });
      verifier.publicCert = publicCert;

      expect(() => verifier.checkSignature(xml)).to.throw(
        /requires a secret key, but was given a asymmetric key/,
      );
      expect(verifier.getSignedReferences()).to.be.empty;
    });

    it("refuses to verify an RSA signature when handed an HMAC shared secret", function () {
      const xml = sign(rsaSha256, sha256);
      const verifier = loadSignature(xml);
      verifier.publicCert = hmacKey;

      expect(() => verifier.checkSignature(xml)).to.throw(
        /requires a asymmetric key, but was given a secret key/,
      );
      expect(verifier.getSignedReferences()).to.be.empty;
    });

    it("still verifies an HMAC signature whose shared secret is supplied", function () {
      const xml = sign(hmacSha1, sha1, hmacKey);
      const verifier = loadSignature(xml, { hmac: true });
      verifier.publicCert = hmacKey;

      expect(verifier.checkSignature(xml)).to.be.true;
      expect(verifier.getSignedReferences()).to.have.lengthOf(1);
    });

    it("accepts keys handed over as KeyObjects, of either key family", function () {
      const rsaXml = sign(rsaSha256, sha256, crypto.createPrivateKey(privateKey));
      const rsaVerifier = loadSignature(rsaXml);
      rsaVerifier.publicCert = crypto.createPublicKey(publicCert);
      expect(rsaVerifier.checkSignature(rsaXml)).to.be.true;

      const hmacXml = sign(hmacSha1, sha1, crypto.createSecretKey(hmacKey));
      const hmacVerifier = loadSignature(hmacXml, { hmac: true });
      hmacVerifier.publicCert = crypto.createSecretKey(hmacKey);
      expect(hmacVerifier.checkSignature(hmacXml)).to.be.true;
    });

    it("classifies a bare SPKI DER public key as an asymmetric key", function () {
      const spkiDer = crypto.createPublicKey(publicCert).export({ format: "der", type: "spki" });
      const certificateDer = fs.readFileSync("./test/static/client_public.der");

      expect(getKeyType(spkiDer)).to.equal("asymmetric");
      expect(getKeyType(certificateDer)).to.equal("asymmetric");
      expect(getKeyType(hmacKey)).to.equal("secret");
    });

    /* eslint-disable deprecation/deprecation */
    it("reports the mismatch through the callback forms instead of throwing", function (done) {
      const signer = new SignedXml();
      signer.enableHMAC();
      signer.privateKey = privateKey;
      signer.signatureAlgorithm = hmacSha1;
      signer.canonicalizationAlgorithm = exclusiveC14n;
      signer.addReference({
        xpath: "//*[local-name(.)='book']",
        digestAlgorithm: sha1,
        transforms: [exclusiveC14n],
      });

      signer.computeSignature("<library><book>Harry Potter</book></library>", (error) => {
        expect(error?.message).to.match(/requires a secret key/);

        const xml = sign(hmacSha1, sha1, hmacKey);
        const verifier = loadSignature(xml, { hmac: true });
        verifier.publicCert = publicCert;
        verifier.checkSignature(xml, (verifyError) => {
          expect(verifyError?.message).to.match(/requires a secret key/);
          expect(verifier.getSignedReferences()).to.be.empty;
          done();
        });
      });
    });
    /* eslint-enable deprecation/deprecation */
  });

  describe("custom registered algorithms", function () {
    class MySignatureAlgorithm {
      getSignature(signedInfo: string, key: crypto.KeyLike): string {
        void key;
        return Buffer.from(signedInfo).toString("base64");
      }

      verifySignature(material: string, key: crypto.KeyLike, signatureValue: string): boolean {
        void key;
        return Buffer.from(material).toString("base64") === signatureValue;
      }

      getAlgorithmName(): string {
        return "urn:example:custom-signature";
      }
    }

    class MyDigest {
      getHash(xml: string): string {
        return Buffer.from(xml).toString("base64");
      }

      getAlgorithmName(): string {
        return "urn:example:custom-digest";
      }
    }

    it("signs and verifies after the caller registers the custom algorithms", function () {
      const xml = "<library><book>Harry Potter</book></library>";
      const signer = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: exclusiveC14n,
        signatureAlgorithm: "urn:example:custom-signature",
      });
      signer.SignatureAlgorithms["urn:example:custom-signature"] = MySignatureAlgorithm;
      signer.HashAlgorithms["urn:example:custom-digest"] = MyDigest;
      signer.addReference({
        xpath: "//*[local-name(.)='book']",
        digestAlgorithm: "urn:example:custom-digest",
        transforms: [exclusiveC14n],
      });
      signer.computeSignature(xml);
      const signedXml = signer.getSignedXml();

      const verifier = loadSignature(signedXml);
      verifier.SignatureAlgorithms["urn:example:custom-signature"] = MySignatureAlgorithm;
      verifier.HashAlgorithms["urn:example:custom-digest"] = MyDigest;
      verifier.publicCert = publicCert;

      expect(verifier.checkSignature(signedXml)).to.be.true;
    });
  });
});
