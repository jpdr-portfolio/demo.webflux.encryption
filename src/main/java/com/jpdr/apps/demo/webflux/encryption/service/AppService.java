package com.jpdr.apps.demo.webflux.encryption.service;

import com.jpdr.apps.demo.webflux.encryption.service.dto.PayloadDto;
import reactor.core.publisher.Mono;

public interface AppService {

  Mono<PayloadDto> encryptPayload(Object payload);
  Mono<Object> decryptPayload(PayloadDto payload, String key, String vector);

}
