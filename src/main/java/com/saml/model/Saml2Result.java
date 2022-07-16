package com.saml.model;

import com.saml.exception.Saml2Exception;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public final class Saml2Result {

  private boolean isValid;

  private String responseRaw;

  private String responseB64Decoded;
  
  private String responseB64PrettyFormat;

  private Saml2Exception samlEx;

}
