package com.saml.response.main;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

public class SamlResponse {

  private static final Logger LOGGER = LoggerFactory.getLogger(SamlResponse.class);

  private static final String CERT = "/xml/cert.crt";

  private static final String BAD_XML = "/xml/SAML_BAD.txt";

  private static final String XML_ENC_SAML = "/xml/EncryptedSaml.txt";

  private static final String XML_SAML2 = "/xml/SAML2.xml";

  private static final String ERROR = "Error: ";

  public static void main(String[] args) {
    try {
      // Se lee el CRT
      InputStream inputStreamCert = SamlResponse.class.getResourceAsStream(CERT);
      // Se genera el objeto Credential a partir del CRT
      Credential credential = getBasicX509Credential(inputStreamCert);

      // Se lee el xml encriptado saml
      InputStream inputStreamEnc = SamlResponse.class.getResourceAsStream(XML_ENC_SAML);

      // Se lee el xml encriptado saml con el xml mal anidado
      InputStream inputStreamXmlBad = SamlResponse.class.getResourceAsStream(BAD_XML);

      // Se lee el xml encriptado saml con el xml mal anidado, el cual será arreglado
      InputStream inputStreamFixXmlBad = SamlResponse.class.getResourceAsStream(BAD_XML);

      // Se lee el xml saml2
      InputStream inputStream = SamlResponse.class.getResourceAsStream(XML_SAML2);

      InitializationService.initialize();

      LOGGER.info("===============INIT V A L I D A N D O   S A M L 2===============");
      validateSaml2(inputStream, credential);
      LOGGER.info("=============== END V A L I D A N D O   S A M L 2===============\n");

      LOGGER.info("===============INIT V A L I D A N D O   S A M L  ===============");
      validateSaml(inputStreamEnc, credential, Boolean.FALSE);
      LOGGER.info("=============== END V A L I D A N D O   S A M L  ===============\n");

      LOGGER.info("===============INIT V A L I D A N D O   S A M L  BAD_XML ============");
      validateSaml(inputStreamXmlBad, credential, Boolean.TRUE);
      LOGGER.info("=============== END V A L I D A N D O   S A M L  BAD_XML ============\n");

      LOGGER.info("===============INIT V A L I D A N D O   S A M L  FIX BAD_XML ==========");
      validateSaml(XmlUtil.fixXml(inputStreamFixXmlBad), credential, Boolean.TRUE);
      LOGGER.info("=============== END V A L I D A N D O   S A M L  FIX BAD_XML ==========");

    } catch (Exception ex) {
      LOGGER.error(ERROR, ex);
    }
  }

  /**
   * Method que valida el SAML
   */
  private static void validateSaml(InputStream inputStreamEnc, Credential credential,
      Boolean printXml) {
    try {
      // se obtiene la cadena encriptada y se desencripta el SAML
      String encryptedString = IOUtils.toString(inputStreamEnc, StandardCharsets.UTF_8);

      byte[] byteString = Base64.decodeBase64(encryptedString);
      // Esta parte es para validar e imprimir el XML de forma bonita (se puede omitir)
      printXml(byteString, printXml);
      // Se obtiene el objeto Response a partir del xml SAML
      Response response = getResponse(byteString);

      // Aquí se imprimen algunos datos del SAML solo para comprobar
      List<Assertion> assertionsList = response.getAssertions();
      LOGGER.info("Assertions: {}", assertionsList);
      for (Assertion assertion : assertionsList) {
        LOGGER.info("ElementQName: {}", assertion.getElementQName());
        LOGGER.info("Signature: {}", assertion.getSignature());
        // Se obtiene y valida el Signature
        assertionSignatureValidation(assertion.getSignature(), credential);
      }
    } catch (Exception ex) {
      LOGGER.error(ERROR, ex);
    }
  }

  /**
   * Method que sirve para imprimir el XML formateado de forma bonita
   */
  private static void printXml(byte[] byteString, Boolean printXml) {
    if (Boolean.TRUE.equals(printXml)) {
      XmlUtil.format(new String(byteString));
    }
  }

  /**
   * Method que valida el signature SAML
   */
  private static void assertionSignatureValidation(Signature signature, Credential credential)
      throws SignatureException {
    // Se valida que signature no venga nulo
    if (signature == null) {
      LOGGER.info("Signature null");
    } else {
      // Se valida el Signature
      SignatureValidator.validate(signature, credential);
      X509Data x509Data = Objects.requireNonNull(signature.getKeyInfo()).getX509Datas().stream()
          .findFirst().orElse(null);
      assert x509Data != null;
      LOGGER.info("x509Data {}", x509Data.getX509Certificates().stream().findFirst().orElse(null));
    }
    LOGGER.info("Signature Validator ok!");
  }

  /**
   * Method que valida el SAML2
   */
  private static void validateSaml2(InputStream inputStream, Credential credential) {
    try {
      // Se pasa el inputStream a cadena de bytes
      byte[] xmlBytes = IOUtils.toByteArray(inputStream);

      // Se obtiene el objeto Response a partir del xml SAML
      Response response = getResponse(xmlBytes);

      // Aquí se imprimen algunos datos del SAML como comprobación
      LOGGER.info("EncryptedAssertions: {}", response.getEncryptedAssertions());
      for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
        LOGGER.info("ElementQName: {}", encryptedAssertion.getElementQName());
        LOGGER.info("Algorithm: {}",
            Objects.requireNonNull(encryptedAssertion.getEncryptedData().getEncryptionMethod())
                .getAlgorithm());
      }
      LOGGER.info("Signature: {}", response.getSignature());

      // Se obtiene el objeto Signature
      Signature signature = response.getSignature();
      // Se valida que signature no venga nulo
      if (signature == null) {
        LOGGER.info("Signature null");
      } else {
        // Se valida el Signature
        SignatureValidator.validate(signature, credential);
        LOGGER.info("Signature Validator ok!");
      }
    } catch (Exception ex) {
      LOGGER.error(ERROR, ex);
    }
  }

  /**
   * Method que obtiene el objeto tipo Response del SAML o SAML2
   */
  private static Response getResponse(byte[] xmlBytes)
      throws XMLParserException, UnmarshallingException {
    // Se registra el XML Object
    XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
    // Se genera el Document de la cadena de bytes del XML
    Document messageDoc = registry.getParserPool().parse(new ByteArrayInputStream(xmlBytes));
    // Se construye el objeto Unmarshalled
    Unmarshaller unmarshaller =
        registry.getUnmarshallerFactory().getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
    // Se hace binding de objeto Unmarshalled a objeto de tipo Response con el SAML
    assert unmarshaller != null;
    return (Response) unmarshaller.unmarshall(messageDoc.getDocumentElement());
  }

  /**
   * Obtiene el basic x509 credential a partir del certificado crt
   */
  private static BasicX509Credential getBasicX509Credential(InputStream inputStream) {
    try (ByteArrayInputStream certInputStream =
        new ByteArrayInputStream(IOUtils.toByteArray(inputStream))) {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      X509Certificate certificate =
          (X509Certificate) certFactory.generateCertificate(certInputStream);
      return new BasicX509Credential(certificate);
    } catch (Exception ex) {
      LOGGER.error(ERROR, ex);
      return null;
    }
  }
}
