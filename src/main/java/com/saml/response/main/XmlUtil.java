package com.saml.response.main;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
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
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class XmlUtil {

  private static final Logger LOGGER = LoggerFactory.getLogger(XmlUtil.class);

  private static final String ASSERTION = "saml:Assertion";

  private static final String SIGNATURE = "ds:Signature";

  private XmlUtil() {}

  /**
   * Method que se encarga de anidar de forma correcta el SAML
   */
  public static InputStream fixXml(InputStream inputStreamBadXml) throws IOException {
    // ESTA PARTE OBTIENE EL XML ENCRIPTADO DE EJEMPLO (XML MAL FORMADO)
    String xmlString = IOUtils.toString(inputStreamBadXml, StandardCharsets.UTF_8);
    try {
      // ESTA PARTE DECODIFICA EL SAMLResponse (XML DE EJEMPLO MAL FORMADO)
      byte[] bytesRes = Base64.decodeBase64(xmlString.getBytes(StandardCharsets.UTF_8));
      String response = new String(bytesRes, StandardCharsets.UTF_8);

      // ESTA PARTE CONVIERTE EL XML A UN objeto de tipo Element
      Element elementXml = generateElementResponse(response);

      // Esta parte genera el NodeList a partir del objeto ELEMENT
      NodeList nodeList = elementXml.getChildNodes();

      // Genera NodeList-Stream para iterar NodeList y obtener Signature
      Stream<Node> streamNode1 = getInputStream(nodeList);
      // ESTA PARTE OBTIENE EL Signature Y LO CONVIERTE EN el [Node] a remover del ELEMENT
      Node nodeSign =
          streamNode1.filter(node -> isValidNode(node, SIGNATURE)).findFirst().orElse(null);

      // Si se encontró NODE Signature como NODE 1 se comienza la modification del ELEMENT
      if (nodeSign != null) {
        // Se elimina el Signature del ELEMENT
        elementXml.removeChild(nodeSign);
        // Genera NodeList-Stream para encontrar Assertion
        Stream<Node> streamNode2 = getInputStream(nodeList);
        // Esta parte busca el NODE Assertion para insertarle como hijo el Signature NODE
        streamNode2.forEach(node -> {
          if (isValidNode(node, ASSERTION)) {
            // Se inserta como hijo del Assertion el Signature en el objeto ELEMENT
            elementXml.getElementsByTagName(ASSERTION).item(0).appendChild(nodeSign);
          }
        });

        // El objeto ELEMENT lo convierte a StringWriter para poder generar el String del XML
        StringWriter writer = generateStringWriter(elementXml);

        // SE CONVIERTE A CADENA EL XML NODE Y SE CODIFICA
        String xmlStringFinal = writer.toString();
        return generateNewInputStream(xmlStringFinal);
      } else { // No se encontró un NODE Signature como NODE 1, se retorna el mismo xml
        return new ByteArrayInputStream(xmlString.getBytes(StandardCharsets.UTF_8));
      }
    } catch (Exception ex) {
      LOGGER.error("ERROR EL XML NO SE FORMATEO DE FORMA CORRECTA: ", ex);
      return new ByteArrayInputStream(xmlString.getBytes(StandardCharsets.UTF_8));
    }
  }

  /**
   * Method que convierte el XML a un objeto de tipo ELEMENT
   */
  private static Element generateElementResponse(String response)
      throws ParserConfigurationException, IOException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
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
   * Method que a partir del XML re-acomodado lo codifica en Base64 y genera InputStream
   */
  private static InputStream generateNewInputStream(String xmlStringFinal) {
    byte[] bytes = Base64.encodeBase64(xmlStringFinal.getBytes());
    String xmlEncryptedFinal = new String(bytes, StandardCharsets.UTF_8);
    return new ByteArrayInputStream(xmlEncryptedFinal.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Method que sirve solo para imprimir de forma bonita el XML
   */
  public static void format(String xml) {
    try {
      final InputSource src = new InputSource(new StringReader(xml));
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      final Node document = factory.newDocumentBuilder().parse(src).getDocumentElement();
      final Boolean keepDeclaration = xml.startsWith("<?xml");
      final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
      final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
      final LSSerializer writer = impl.createLSSerializer();

      writer.getDomConfig().setParameter("format-pretty-print", Boolean.TRUE);
      writer.getDomConfig().setParameter("xml-declaration", keepDeclaration);

      String xmlResult = writer.writeToString(document);
      LOGGER.info(xmlResult);
    } catch (Exception e) {
      LOGGER.info("ERROR: ", e);
    }
  }
}
