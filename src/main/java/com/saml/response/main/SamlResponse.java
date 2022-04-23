package com.saml.response.main;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.w3c.dom.Document;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

public class SamlResponse {

  private static final Logger LOGGER = LoggerFactory.getLogger(SamlResponse.class);
  
  public static void main(String[] args) {
    String contexto = "classpath*:**/spring/applicationContext.xml";
    try (ClassPathXmlApplicationContext applicationContext =
        new ClassPathXmlApplicationContext(contexto)) {
      // Aqui se lee el CRT
      InputStream inputStreamCert = SamlResponse.class.getResourceAsStream("/xml/cert.crt");
      // Se genera el objeto Credential a partir del CRT
      Credential credential = getBasicX509Credential(inputStreamCert);
      
      // Aqui se lee el xml encriptado saml
      InputStream inputStreamEncr = SamlResponse.class.getResourceAsStream("/xml/EncryptedSaml.txt");
      
      // Aqui se lee el xml saml
      InputStream inputStream = SamlResponse.class.getResourceAsStream("/xml/SAML2.xml");
      
      InitializationService.initialize();
      
      LOGGER.info("================INIT V A L I D A N D O   S A M L 2================");
      validateSaml2(inputStream, credential);
      LOGGER.info("================ END V A L I D A N D O   S A M L 2================\n");

      LOGGER.info("================INIT V A L I D A N D O   S A M L  ================");
      validateSaml(inputStreamEncr, credential);
      LOGGER.info("================ END V A L I D A N D O   S A M L  ================");

      // Aqui se cierran los inputStreams (debido a la forma en que se leyeron los archivos)
      inputStream.close();
      inputStreamCert.close();
      inputStreamEncr.close();
    } catch (Exception ex) {
      LOGGER.error("Error: ", ex);
    }
  }
  
  /**
   * Metodo que valida el SAML
   * @param inputStreamEncr
   * @param credential
   */
  private static void validateSaml(InputStream inputStreamEncr, Credential credential) {
    try {
      // Aqui se obtiene la cadena encriptada y se desencripta el SAML
      String encryptedString = IOUtils.toString(inputStreamEncr, StandardCharsets.UTF_8);
      byte[] byteString = Base64.decodeBase64(encryptedString);
      // Se obtiene el objeto Response a partir del xml SAML
      Response response = getResponse(byteString);
      
      /** Aquí se imprimen algunos datos del SAML como comprobacion **/
      LOGGER.info("Assertions: {}", response.getAssertions());
      for (Assertion assertion: response.getAssertions()) {
        LOGGER.info("ElementQName: {}", assertion.getElementQName());
        LOGGER.info("Signature: {}", assertion.getSignature());
        // Aqui se obtiene y valida el Signature
        assertionSignatureValidation(assertion.getSignature(), credential);
      }
    } catch(Exception ex) {
      LOGGER.error(ex.getMessage(), ex);
    }
  }

  private static void assertionSignatureValidation(Signature signature, Credential credential)
      throws SignatureException {
    // Se valida que signature no venga nulo
    if (signature == null) {
      LOGGER.info("Signature null");
    } else {
      // Se valida el Signature
      SignatureValidator.validate(signature, credential);
      LOGGER.info("Signature Validator ok!");
    }
  }

  /**
   * Metodo que valida el SAML2
   * @param inputStream
   * @param credential
   */
  private static void validateSaml2(InputStream inputStream, Credential credential) {
    try {
      // Aqui se pasa el inputStream a cadena de bytes
      byte[] xmlBytes =  IOUtils.toByteArray(inputStream);
      
      // Se obtiene el objeto Response a partir del xml SAML
      Response response = getResponse(xmlBytes);
      
      /** Aquí se imprimen algunos datos del SAML como comprobacion **/
      LOGGER.info("EncryptedAssertions: {}", response.getEncryptedAssertions());
      for (EncryptedAssertion encryptedAssertion: response.getEncryptedAssertions()) {
        LOGGER.info("ElementQName: {}", encryptedAssertion.getElementQName());
        LOGGER.info("Algorithm: {}", encryptedAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm());
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
    } catch(Exception ex) {
      LOGGER.error(ex.getMessage(), ex);
    } 
  }
  
  private static Response getResponse(byte[] xmlBytes) throws XMLParserException, UnmarshallingException {
    // Se registra el XML Object
    XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
    // Se genera el Document de la cadena de bytes del XML
    Document messageDoc = registry.getParserPool().parse(new ByteArrayInputStream(xmlBytes));
    // Se construye el objeto Unmarshaller
    Unmarshaller unmarshaller = registry.getUnmarshallerFactory().getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
    // El objeto Unmarshaller se castea a tipo Response con el SAML
    return (Response) unmarshaller.unmarshall(messageDoc.getDocumentElement());
  }

  private static BasicX509Credential getBasicX509Credential(InputStream inputStream) {
    try(ByteArrayInputStream certInputStream = new ByteArrayInputStream(IOUtils.toByteArray(inputStream))){
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      X509Certificate certificate =
          (X509Certificate) certFactory.generateCertificate(certInputStream);
      return new BasicX509Credential(certificate);
    } catch (Exception ex) {
      LOGGER.error(ex.getMessage(), ex);
      return null;
    }
  }
  
}
