package com.saml.util;

import com.saml.constants.Constants;
import com.saml.exception.Saml2Exception;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

@Slf4j
public class Saml2Util {

  private static final String FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";

  private Saml2Util() {}

  /**
   * Method que se encarga de anidar de forma correcta el SAML
   */
  public static byte[] fixSaml2(byte[] byteString) {
    try {
      String response = new String(Base64.decodeBase64(byteString), StandardCharsets.UTF_8);

      Element elementXml = generateElementResponse(response);
      NodeList nodeList = elementXml.getChildNodes();
      Stream<Node> streamNode1 = getInputStream(nodeList);
      Node nodeSign = streamNode1.filter(node -> isValidNode(node, Constants.SIGNATURE)).findFirst()
          .orElse(null);

      if (nodeSign != null) {
        elementXml.removeChild(nodeSign);
        Stream<Node> streamNode2 = getInputStream(nodeList);
        streamNode2.forEach(node -> {
          if (isValidNode(node, Constants.ASSERTION)) {
            elementXml.getElementsByTagName(Constants.ASSERTION).item(0).appendChild(nodeSign);
          }
        });

        StringWriter writer = generateStringWriter(elementXml);

        return writer.toString().getBytes();
      } else {
        return Base64.decodeBase64(byteString);
      }
    } catch (Exception ex) {
      log.error(Constants.ERROR_XML_FORMAT, ex);
      throw new Saml2Exception(ex.getMessage());
    }
  }

  /**
   * Method que convierte el XML a un objeto de tipo ELEMENT
   */
  private static Element generateElementResponse(String response)
      throws ParserConfigurationException, IOException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature(FEATURE, true);
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8));
    Document doc = db.parse(bis);
    return doc.getDocumentElement();
  }

  /**
   * Method que genera el InputStream de un NodeList para poder Iterarlo
   */
  private static Stream<Node> getInputStream(NodeList nodeList) {
    return IntStream.range(0, nodeList.getLength()).mapToObj(nodeList::item);
  }

  /**
   * Method to valid if node type is ELEMENT NODE [1] and has a NODE NAME
   */
  private static boolean isValidNode(Node node, String nodeName) {
    return node.getNodeType() == Node.ELEMENT_NODE && nodeName.equals(node.getNodeName());
  }

  /**
   * Method que genera el objeto StringWriter a partir del ELEMENT para posteriormente obtener el
   * String del XML
   */
  private static StringWriter generateStringWriter(Element elementXml) throws TransformerException {
    StringWriter writer = new StringWriter();
    TransformerFactory factory = TransformerFactory.newInstance();
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, StringUtils.EMPTY);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, StringUtils.EMPTY);
    Transformer trans = factory.newTransformer();
    trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    trans.transform(new DOMSource(elementXml), new StreamResult(writer));
    return writer;
  }

  /**
   * Method que sirve solo para imprimir de forma bonita el XML
   */
  public static String prettyFormat(String xml) {
    try {
      final InputSource src = new InputSource(new StringReader(xml));
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setFeature(FEATURE, true);
      final Node document = factory.newDocumentBuilder().parse(src).getDocumentElement();
      final Boolean keepDeclaration = xml.startsWith("<?xml");
      final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
      final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
      final LSSerializer writer = impl.createLSSerializer();

      writer.getDomConfig().setParameter("format-pretty-print", Boolean.TRUE);
      writer.getDomConfig().setParameter("xml-declaration", keepDeclaration);

      return writer.writeToString(document);
    } catch (Exception ex) {
      log.error(Constants.ERROR, ex);
      throw new Saml2Exception(ex.getMessage());
    }
  }
}
