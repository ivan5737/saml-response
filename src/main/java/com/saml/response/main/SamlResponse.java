package com.saml.response.main;

import com.saml.constants.Constants;
import com.saml.model.Saml2Result;
import com.saml.service.Saml2Validation;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@Slf4j
public class SamlResponse {

  private static final String CERT = "/xml/cert.crt";

  private static final String ENC_SAML = "/xml/EncryptedSaml.txt";

  private static final String ENC_SAML_BAD = "/xml/EncryptedSamlBad.txt";

  private static final String ENC_SAML_BAD_NEST = "/xml/EncryptedSamlBadNest.txt";

  public static void main(String[] args) {
    try {
      // Se lee el CRT
      InputStream inputStreamCert = SamlResponse.class.getResourceAsStream(CERT);
      byte[] cert = IOUtils.toByteArray(inputStreamCert);

      // Se lee el saml codificado
      InputStream inputStreamEnc = SamlResponse.class.getResourceAsStream(ENC_SAML);
      String samlEnc = IOUtils.toString(inputStreamEnc, StandardCharsets.UTF_8);

      // Se lee saml codificado con una diferencia o error en la info
      InputStream inputStreamBad = SamlResponse.class.getResourceAsStream(ENC_SAML_BAD);
      String samlEncBad = IOUtils.toString(inputStreamBad, StandardCharsets.UTF_8);

      // Se lee saml codificado mal anidado
      InputStream inputStreamBadNest = SamlResponse.class.getResourceAsStream(ENC_SAML_BAD_NEST);
      String samlEncBadNest = IOUtils.toString(inputStreamBadNest, StandardCharsets.UTF_8);


      log.info("===============INIT   V A L I D A N D O   S A M L 2===============");
      Saml2Result result1 = new Saml2Validation().setCert(cert).parse(samlEnc);
      log.info("SAML ENC valido? {}", result1.isValid());
      log.info("================END   V A L I D A N D O   S A M L 2===============\n");

      log.info("===============INIT   V A L I D A N D O   S A M L   BAD===========");
      Saml2Result result2 = new Saml2Validation().setCert(cert).parse(samlEncBad);
      log.info("SAML ENC BAD valido? {}", result2.isValid());
      log.info("================END   V A L I D A N D O   S A M L   BAD===========\n");

      log.info("===============INIT   V A L I D A N D O   S A M L   BAD NEST======");
      Saml2Result result3 = new Saml2Validation().setCert(cert).parse(samlEncBadNest);
      log.info("SAML BAD NEST valido? {}", result3.isValid());
      log.info("================END   V A L I D A N D O   S A M L   BAD NEST======");

      log.info("===============INIT   V A L I D A N D O   S A M L   FIX_BAD_NEST==");
      Saml2Result result4 = new Saml2Validation().fixSaml2().setCert(cert).parse(samlEncBadNest);
      log.info("SAML FIX BAD NEST valido? {}", result4.isValid());
      log.info("================END   V A L I D A N D O   S A M L   FIX_BAD_NEST==");

    } catch (Exception ex) {
      log.error(Constants.ERROR, ex);
    }
  }


}
