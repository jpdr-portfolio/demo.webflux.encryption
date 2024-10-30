package com.jpdr.apps.demo.webflux.encryption.service.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class PayloadDto {
  
  @JsonInclude(Include.NON_NULL)
  String headerKey;
  @JsonInclude(Include.NON_NULL)
  String headerVector;
  String data;
  
}
