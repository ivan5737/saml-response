package com.saml.exception;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

public class Saml2Exception extends RuntimeException {

  private static final long serialVersionUID = 4448062281861119419L;

  @Getter
  private final ExceptionData exceptionData;

  public Saml2Exception(String message, String detail) {
    super();
    this.exceptionData = ExceptionData.builder().message(message).detail(detail).build();
  }

  public Saml2Exception(String message) {
    super();
    this.exceptionData = ExceptionData.builder().message(message).detail(StringUtils.EMPTY).build();
  }

}
