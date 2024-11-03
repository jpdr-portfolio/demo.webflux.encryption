package com.jpdr.apps.demo.webflux.encryption.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jpdr.apps.demo.webflux.encryption.exception.MissingParameterException;
import com.jpdr.apps.demo.webflux.encryption.service.AppService;
import com.jpdr.apps.demo.webflux.encryption.service.EncryptionService;
import com.jpdr.apps.demo.webflux.encryption.service.dto.PayloadDto;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class AppServiceImpl implements AppService {
  
  public static final String PUBLIC_KEY_PROPERTY = "app.key.public";
  public static final String PRIVATE_KEY_PROPERTY = "app.key.private";
  
  private final EncryptionService encryptionService;
  private final Environment env;
  private final ObjectMapper objectMapper;
  
  @PostConstruct
  public void postConstruct(){
    if(env.getProperty(PUBLIC_KEY_PROPERTY) == null){
      throw new MissingParameterException(PUBLIC_KEY_PROPERTY);
    }
    if(env.getProperty(PRIVATE_KEY_PROPERTY) == null){
      throw new MissingParameterException(PRIVATE_KEY_PROPERTY);
    }
  }
  
  @Override
  public Mono<PayloadDto> encryptPayload(Object payload) {
    return Mono.zip(
        Mono.from(this.writeValueAsString(payload))
          .map(decryptedPayload -> decryptedPayload.getBytes(StandardCharsets.UTF_8)),
        Mono.from(Mono.just(env.getProperty(PUBLIC_KEY_PROPERTY))),
        Mono.from(this.encryptionService.getHeaderKeyBytes()),
        Mono.from(this.encryptionService.getHeaderVectorBytes()))
      .flatMap(tuple -> Mono.zip(
          Mono.from(this.encryptionService.encryptRSA(Base64.getEncoder().encodeToString(tuple.getT3()),tuple.getT2())),
          Mono.just(Base64.getEncoder().encodeToString(tuple.getT4())),
          Mono.from(this.encryptionService.encryptAES(tuple.getT1(),
            new SecretKeySpec(tuple.getT3(),  "AES"), tuple.getT4()))))
      .map(tuple -> PayloadDto.builder()
        .headerKey(tuple.getT1())
        .headerVector(tuple.getT2())
        .data(tuple.getT3())
        .build());
  }
  
  @Override
  public Mono<Object> decryptPayload(PayloadDto payload, String key, String vector) {
    return Mono.from(this.encryptionService.decryptAES(payload.getData(),
        vector,key,env.getProperty(PRIVATE_KEY_PROPERTY)))
      .flatMap(this::readTree);
  }
  
  private Mono<String> writeValueAsString(Object object){
    return Mono.fromCallable(() -> objectMapper.writeValueAsString(object))
      .subscribeOn(Schedulers.boundedElastic());
  }
  
  
  private Mono<JsonNode> readTree(String content){
    return Mono.fromCallable(() -> objectMapper.readTree(content))
      .subscribeOn(Schedulers.boundedElastic());
  }
  
}
