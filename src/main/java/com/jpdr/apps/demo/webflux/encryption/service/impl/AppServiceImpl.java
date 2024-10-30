package com.jpdr.apps.demo.webflux.encryption.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jpdr.apps.demo.webflux.encryption.service.AppService;
import com.jpdr.apps.demo.webflux.encryption.service.EncryptionService;
import com.jpdr.apps.demo.webflux.encryption.service.dto.PayloadDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class AppServiceImpl implements AppService {
  
  private final EncryptionService encryptionService;
  private final Environment env;
  private final ObjectMapper objectMapper;
  
  
  @Override
  public Mono<PayloadDto> encryptPayload(Object payload) {
    return Mono.zip(
        Mono.fromCallable(() -> {
          String decryptedPayload = objectMapper.writeValueAsString(payload);
          return decryptedPayload.getBytes(StandardCharsets.UTF_8);
        }),
        Mono.from(Mono.justOrEmpty(env.getProperty("app.key.public"))
          .switchIfEmpty(Mono.defer(() -> Mono.error(new RuntimeException("Missing parameter"))))),
        Mono.from(this.encryptionService.getHeaderKeyBytes()),
        Mono.from(this.encryptionService.getHeaderVectorBytes()))
      .flatMap(tuple -> Mono.zip(
          Mono.from(this.encryptionService.encryptRSA(Base64.getEncoder().encodeToString(tuple.getT3()),tuple.getT2())),
          Mono.just(Base64.getEncoder().encodeToString(tuple.getT4())),
          Mono.from(this.encryptionService.encryptAES(tuple.getT1(),
            new SecretKeySpec(tuple.getT3(), "AES"), tuple.getT4()))))
      .map(tuple -> PayloadDto.builder()
        .headerKey(tuple.getT1())
        .headerVector(tuple.getT2())
        .data(tuple.getT3())
        .build());
  }
  
  @Override
  public Mono<Object> decryptPayload(PayloadDto payload, String key, String vector) {
    return Mono.zip(
        Mono.just(payload.getData()),
        Mono.just(vector),
        Mono.just(key),
        Mono.from(Mono.justOrEmpty(env.getProperty("app.key.private"))
          .switchIfEmpty(Mono.defer(() -> Mono.error(new RuntimeException("Missing parameter")))))
      )
      .flatMap(tuple -> this.encryptionService.decryptAES(tuple.getT1(), tuple.getT2(),
        tuple.getT3(), tuple.getT4()))
      .flatMap(decryptedPayload -> {
          try{
            return Mono.just(objectMapper.readTree(decryptedPayload));
          } catch (JsonProcessingException e) {
            return Mono.error(e);
          }
        });
  }
}
