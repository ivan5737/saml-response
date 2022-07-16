package com.saml.exception;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.util.UUID;

@Data
@Builder
public class ExceptionData implements Serializable {

  private static final long serialVersionUID = -6526322445607220459L;

  private String message;

  private String detail;

  @Builder.Default
  private String uuid = new StringBuilder().append(UUID.randomUUID()).append("-")
      .append(System.currentTimeMillis()).toString();

}
