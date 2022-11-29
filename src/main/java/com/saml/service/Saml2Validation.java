package com.saml.service;

import com.saml.constants.Constants;
import com.saml.exception.Saml2Exception;
import com.saml.model.Saml2Result;
import com.saml.util.Saml2Util;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Slf4j
@Setter(AccessLevel.PRIVATE)
@Getter(AccessLevel.PRIVATE)
public class Saml2Validation {

  private byte[] certData;

  private boolean fixSaml2 = Boolean.FALSE;

  public Saml2Validation setCert(byte[] certData) {
    setCertData(certData);
    return this;
  }

  public Saml2Validation fixSaml2() {
    setFixSaml2(Boolean.TRUE);
    return this;
  }

  /**
   * Method que valida el SAML vs el Cert.
   * 
   * @param encodedString, SAML que recibe codificado en un objeto String.
   * @return objeto Saml2Result, con el resultado de la validacion.
   */
  public Saml2Result parse(String encodedString) {
    try {
      Credential credential = getBasicX509Credential();
      byte[] byteDecodeStr = getByteString(encodedString);
      String decodeStr = new String(byteDecodeStr, StandardCharsets.UTF_8);
      Response response = getResponse(byteDecodeStr);

      for (Assertion assertion : response.getAssertions()) {
        assertionSignatureValidation(assertion.getSignature(), credential);
      }
      return Saml2Result.builder().isValid(Boolean.TRUE).responseRaw(encodedString)
          .responseB64Decoded(decodeStr).responseB64PrettyFormat(Saml2Util.prettyFormat(decodeStr))
          .build();
    } catch (Saml2Exception samlEx) {
      log.debug(Constants.ERROR, samlEx);
      return Saml2Result.builder().isValid(Boolean.FALSE).responseRaw(encodedString).samlEx(samlEx)
          .build();
    }
  }

  /**
   * Metodo que decodifica el SAML2.
   * 
   * @param encodedString, SAML que recibe codificado en un objeto String.
   * @return cadena de bytes decodificada.
   */
  private byte[] getByteString(String encodedString) {
    if (this.isFixSaml2()) {
      return Saml2Util.fixSaml2(encodedString.getBytes(StandardCharsets.UTF_8));
    } else {
      return Base64.decodeBase64(encodedString);
    }
  }

  /**
   * Method que obtiene el objeto tipo Response del SAML o SAML2.
   * 
   * @param byteString, recibe la cadena de bytes del SAML.
   * @return retorna el objeto Response a partir del SAML.
   */
  private Response getResponse(byte[] byteString) {
    try {
      InitializationService.initialize();
      XMLObjectProviderRegistry registry =
          ConfigurationService.get(XMLObjectProviderRegistry.class);
      Document messageDoc = registry.getParserPool().parse(new ByteArrayInputStream(byteString));
      Unmarshaller unmarshaller =
          registry.getUnmarshallerFactory().getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
      return (Response) unmarshaller.unmarshall(messageDoc.getDocumentElement());
    } catch (Exception ex) {
      log.debug(Constants.ERROR, ex);
      throw new Saml2Exception(Constants.GENERATING_RESPONSE, ex.getMessage());
    }
  }

  /**
   * Method que valida el signature del SAML con el CERT.
   * 
   * @param signature objecto que recibe el metodo para ser validado.
   * @param credential objecto que recibe para validar el Signature, Credential es el Cert.
   */
  private void assertionSignatureValidation(Signature signature, Credential credential) {
    if (signature == null) {
      log.debug(Constants.ERROR_SIGN);
      throw new Saml2Exception(Constants.VALIDATION_SIGNATURE_NULL);
    } else {
      try {
        SignatureValidator.validate(signature, credential);
        log.debug("Signature Validator ok!");
      } catch (SignatureException sigex) {
        log.debug(Constants.ERROR, sigex);
        throw new Saml2Exception(Constants.VALIDATION_SIGNATURE, sigex.getMessage());
      }
    }
  }

  /**
   * Get the basic x509 credential from the crt certificate.
   * 
   * @return the BasicX509Credential object from CRT.
   */
  private BasicX509Credential getBasicX509Credential() {
    if (!ArrayUtils.isNotEmpty(getCertData()))
      throw new Saml2Exception(Constants.ERROR_CREDENTIAL);

    try (ByteArrayInputStream certInputStream = new ByteArrayInputStream(this.getCertData())) {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      X509Certificate certificate =
          (X509Certificate) certFactory.generateCertificate(certInputStream);
      return new BasicX509Credential(certificate);
    } catch (Exception ex) {
      log.debug(Constants.ERROR, ex);
      throw new Saml2Exception(Constants.GETTING_CREDENTIAL, ex.getMessage());
    }
  }
}
