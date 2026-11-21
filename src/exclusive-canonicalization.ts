import type {
  CanonicalizationOrTransformationAlgorithm,
  CanonicalizationOrTransformationAlgorithmProcessOptions,
  NamespacePrefix,
} from "./types";
import * as utils from "./utils";
import * as isDomNode from "@xmldom/is-dom-node";
import { deprecate } from "util";

const warnInclusiveNamespacesNamespace = deprecate(
  () => {},
  "Reading an `InclusiveNamespaces` element that is not in the `http://www.w3.org/2001/10/xml-exc-c14n#` namespace is deprecated, and a signature that has one will not verify in version 7.0. xml-crypto 6.3.2 and earlier wrote one when signing with `xml-exc-c14n#WithComments` and a prefix list, so sign those documents again.",
  "XML_CRYPTO_INCLUSIVE_NAMESPACES_NAMESPACE",
);

// https://www.w3.org/TR/xml-exc-c14n/#sec-Use
export function warnUnlessExclusiveC14nNamespace(inclusiveNamespaces: Element): void {
  if (inclusiveNamespaces.namespaceURI !== "http://www.w3.org/2001/10/xml-exc-c14n#") {
    warnInclusiveNamespacesNamespace();
  }
}

export class ExclusiveCanonicalization implements CanonicalizationOrTransformationAlgorithm {
  protected includeComments = false;

  constructor() {
    this.includeComments = false;
  }

  attrCompare(a, b) {
    if (!a.namespaceURI && b.namespaceURI) {
      return -1;
    }
    if (!b.namespaceURI && a.namespaceURI) {
      return 1;
    }

    const left = a.namespaceURI + a.localName;
    const right = b.namespaceURI + b.localName;

    if (left === right) {
      return 0;
    } else if (left < right) {
      return -1;
    } else {
      return 1;
    }
  }

  nsCompare(a, b) {
    const attr1 = a.prefix;
    const attr2 = b.prefix;
    if (attr1 === attr2) {
      return 0;
    }
    return attr1.localeCompare(attr2);
  }

  renderAttrs(node) {
    let i;
    let attr;
    const res: string[] = [];
    const attrListToRender: Attr[] = [];

    if (isDomNode.isCommentNode(node)) {
      return this.renderComment(node);
    }

    if (node.attributes) {
      for (i = 0; i < node.attributes.length; ++i) {
        attr = node.attributes[i];
        if (attr.name === "xmlns" || attr.prefix === "xmlns") {
          continue;
        }
        attrListToRender.push(attr);
      }
    }

    attrListToRender.sort(this.attrCompare);

    for (attr of attrListToRender) {
      res.push(" ", attr.name, '="', utils.encodeSpecialCharactersInAttribute(attr.value), '"');
    }

    return res.join("");
  }

  /**
   * Create the string of all namespace declarations that should appear on this element
   *
   * @param {Node} node. The node we now render
   * @param {Array} prefixesInScope. The prefixes defined on this node
   *                parents which are a part of the output set
   * @param {String} defaultNs. The current default namespace
   * @return {String}
   * @deprecated Will be private in 7.0. Call {@link process} instead of calling or overriding it.
   * @api private
   */
  renderNs(
    node,
    prefixesInScope,
    defaultNs,
    defaultNsForPrefix,
    inclusiveNamespacesPrefixList: string[],
  ) {
    utils.warnOutsideProcess(this);
    let i;
    let attr;
    const res: string[] = [];
    let newDefaultNs = defaultNs;
    const nsListToRender: NamespacePrefix[] = [];
    const currNs = node.namespaceURI || "";

    //handle the namespaceof the node itself
    if (node.prefix) {
      if (
        !utils.isPrefixInScope(
          prefixesInScope,
          node.prefix,
          node.namespaceURI || defaultNsForPrefix[node.prefix],
        )
      ) {
        nsListToRender.push({
          prefix: node.prefix,
          namespaceURI: node.namespaceURI || defaultNsForPrefix[node.prefix],
        });
        prefixesInScope.push({
          prefix: node.prefix,
          namespaceURI: node.namespaceURI || defaultNsForPrefix[node.prefix],
        });
      }
    }

    const currentDefaultNs = node.prefix
      ? (node.getAttributeNode("xmlns")?.value ?? defaultNs)
      : currNs;
    if (
      (!node.prefix || inclusiveNamespacesPrefixList.includes("#default")) &&
      defaultNs !== currentDefaultNs
    ) {
      newDefaultNs = currentDefaultNs;
      res.push(' xmlns="', utils.encodeSpecialCharactersInAttribute(newDefaultNs), '"');
    }

    //handle the attributes namespace
    if (node.attributes) {
      for (i = 0; i < node.attributes.length; ++i) {
        attr = node.attributes[i];

        //handle all prefixed attributes that are included in the prefix list and where
        //the prefix is not defined already
        if (
          attr.prefix === "xmlns" &&
          !utils.isPrefixInScope(prefixesInScope, attr.localName, attr.value) &&
          inclusiveNamespacesPrefixList.indexOf(attr.localName) >= 0
        ) {
          nsListToRender.push({ prefix: attr.localName, namespaceURI: attr.value });
          prefixesInScope.push({ prefix: attr.localName, namespaceURI: attr.value });
        }

        //handle all prefixed attributes that are not xmlns definitions and where
        //the prefix is not defined already
        if (
          attr.prefix &&
          !utils.isPrefixInScope(prefixesInScope, attr.prefix, attr.namespaceURI) &&
          attr.prefix !== "xmlns" &&
          attr.prefix !== "xml"
        ) {
          nsListToRender.push({ prefix: attr.prefix, namespaceURI: attr.namespaceURI });
          prefixesInScope.push({ prefix: attr.prefix, namespaceURI: attr.namespaceURI });
        }
      }
    }

    nsListToRender.sort(this.nsCompare);

    //render namespaces
    for (const p of nsListToRender) {
      const namespaceURI = utils.encodeSpecialCharactersInAttribute(p.namespaceURI);
      res.push(" xmlns:", p.prefix, '="', namespaceURI, '"');
    }

    return { rendered: res.join(""), newDefaultNs: newDefaultNs };
  }

  /**
   * @param node Node
   * @deprecated Will be private in 7.0. Call {@link process} instead of calling or overriding it.
   */
  processInner(
    node,
    prefixesInScope,
    defaultNs,
    defaultNsForPrefix,
    inclusiveNamespacesPrefixList: string[],
  ) {
    utils.warnOutsideProcess(this);
    if (isDomNode.isDocumentNode(node)) {
      const res: string[] = [];
      for (let i = 0; i < node.childNodes.length; i++) {
        const child = node.childNodes[i];
        if (isDomNode.isCommentNode(child)) {
          if (this.includeComments) {
            res.push(this.renderComment(child, true));
          }
          continue;
        }
        if (utils.isCanonicalDocumentChild(child)) {
          res.push(
            /* eslint-disable-next-line deprecation/deprecation */
            this.processInner(
              child,
              prefixesInScope,
              defaultNs,
              defaultNsForPrefix,
              inclusiveNamespacesPrefixList,
            ),
          );
        }
      }
      return res.join("\n");
    }
    if (isDomNode.isCommentNode(node)) {
      return this.renderComment(node);
    }
    if (isDomNode.isProcessingInstructionNode(node)) {
      return utils.renderProcessingInstruction(node);
    }
    if (node.data) {
      return utils.encodeSpecialCharactersInText(node.data);
    }

    if (isDomNode.isElementNode(node)) {
      let i;
      let pfxCopy;
      /* eslint-disable-next-line deprecation/deprecation */
      const ns = this.renderNs(
        node,
        prefixesInScope,
        defaultNs,
        defaultNsForPrefix,
        inclusiveNamespacesPrefixList,
      );
      const res = ["<", node.tagName, ns.rendered, this.renderAttrs(node), ">"];

      for (i = 0; i < node.childNodes.length; ++i) {
        pfxCopy = prefixesInScope.slice(0);
        res.push(
          /* eslint-disable-next-line deprecation/deprecation */
          this.processInner(
            node.childNodes[i],
            pfxCopy,
            ns.newDefaultNs,
            defaultNsForPrefix,
            inclusiveNamespacesPrefixList,
          ),
        );
      }

      res.push("</", node.tagName, ">");
      return res.join("");
    }

    throw new Error(`Unable to exclusive canonicalize node type: ${node.nodeType}`);
  }

  // Thanks to deoxxa/xml-c14n for comment renderer
  renderComment(node: Comment, documentChild = false) {
    if (!this.includeComments) {
      return "";
    }

    const encodedText = utils.encodeSpecialCharactersInText(node.data);
    if (documentChild) {
      return `<!--${encodedText}-->`;
    }

    const isOutsideDocument = node.ownerDocument === node.parentNode;
    let isBeforeDocument = false;
    let isAfterDocument = false;

    if (isOutsideDocument) {
      let nextNode: ChildNode | null = node;
      let previousNode: ChildNode | null = node;

      while (nextNode != null) {
        if (nextNode === node.ownerDocument.documentElement) {
          isBeforeDocument = true;
          break;
        }

        nextNode = nextNode.nextSibling;
      }

      while (previousNode != null) {
        if (previousNode === node.ownerDocument.documentElement) {
          isAfterDocument = true;
          break;
        }

        previousNode = previousNode.previousSibling;
      }
    }

    const afterDocument = isAfterDocument ? "\n" : "";
    const beforeDocument = isBeforeDocument ? "\n" : "";
    return `${afterDocument}<!--${encodedText}-->${beforeDocument}`;
  }

  /**
   * Perform canonicalization of the given node
   *
   * @api public
   */
  process(
    node: Element | Document,
    options: CanonicalizationOrTransformationAlgorithmProcessOptions,
  ): string {
    options = options || {};
    let inclusiveNamespacesPrefixList = options.inclusiveNamespacesPrefixList || [];
    const defaultNs = options.defaultNs || "";
    const defaultNsForPrefix = options.defaultNsForPrefix || {};

    /**
     * If the inclusiveNamespacesPrefixList has not been explicitly provided then look it up in CanonicalizationMethod/InclusiveNamespaces
     */
    if (!utils.isArrayHasLength(inclusiveNamespacesPrefixList)) {
      const CanonicalizationMethod = utils.findChildren(node, "CanonicalizationMethod");
      if (CanonicalizationMethod.length !== 0) {
        const inclusiveNamespaces = utils.findChildren(
          CanonicalizationMethod[0],
          "InclusiveNamespaces",
        );
        if (inclusiveNamespaces.length !== 0) {
          warnUnlessExclusiveC14nNamespace(inclusiveNamespaces[0]);
          inclusiveNamespacesPrefixList = (
            inclusiveNamespaces[0].getAttribute("PrefixList") || ""
          ).split(" ");
        }
      }
    }

    // Snapshot the caller's prefix context: it belongs to this document, not to canonicalization.
    inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList.slice();
    const ancestorNamespaces = (options.ancestorNamespaces || []).map((namespace) => ({
      prefix: namespace.prefix,
      namespaceURI: namespace.namespaceURI,
    }));

    /**
     * If you have a PrefixList then use it and the ancestors to add the necessary namespaces
     */
    const declarationsToRender = new Map<string, string>();
    const elem = isDomNode.isDocumentNode(node) ? node.documentElement : node;
    if (utils.isArrayHasLength(inclusiveNamespacesPrefixList) && elem != null) {
      for (const prefix of inclusiveNamespacesPrefixList) {
        if (declarationsToRender.has(prefix)) {
          continue;
        }

        const declaredOnElement =
          prefix === "#default"
            ? elem.hasAttribute("xmlns")
            : elem.hasAttribute(`xmlns:${prefix}`);
        if (declaredOnElement) {
          continue;
        }

        const ancestorNamespace = ancestorNamespaces.find((namespace) =>
          prefix === "#default" ? namespace.prefix === "" : namespace.prefix === prefix,
        );
        if (ancestorNamespace != null) {
          declarationsToRender.set(prefix, ancestorNamespace.namespaceURI);
        }
      }
    }

    let canonicalNode: Element | Document = node;
    if (declarationsToRender.size > 0) {
      const clone = node.cloneNode(true);
      if (isDomNode.isDocumentNode(clone)) {
        canonicalNode = clone;
      } else if (isDomNode.isElementNode(clone)) {
        canonicalNode = clone;
      } else {
        throw new Error(`Unable to exclusive canonicalize node type: ${clone.nodeType}`);
      }

      const canonicalElem = isDomNode.isDocumentNode(canonicalNode)
        ? canonicalNode.documentElement
        : canonicalNode;
      if (canonicalElem == null) {
        throw new Error(`Unable to exclusive canonicalize node type: ${node.nodeType}`);
      }

      for (const [prefix, namespaceURI] of declarationsToRender) {
        canonicalElem.setAttributeNS(
          "http://www.w3.org/2000/xmlns/",
          prefix === "#default" ? "xmlns" : `xmlns:${prefix}`,
          namespaceURI,
        );
      }
    }

    return utils.insideProcess(this, ExclusiveCanonicalization.prototype, () =>
      /* eslint-disable-next-line deprecation/deprecation */
      this.processInner(
        canonicalNode,
        [],
        defaultNs,
        defaultNsForPrefix,
        inclusiveNamespacesPrefixList,
      ),
    );
  }

  getAlgorithmName() {
    return "http://www.w3.org/2001/10/xml-exc-c14n#";
  }
}

export class ExclusiveCanonicalizationWithComments extends ExclusiveCanonicalization {
  constructor() {
    super();
    this.includeComments = true;
  }

  getAlgorithmName() {
    return "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
  }
}
