package com.jpdr.apps.demo.webflux.encryption.controller;

import com.jpdr.apps.demo.webflux.encryption.service.AppService;
import com.jpdr.apps.demo.webflux.encryption.service.dto.PayloadDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AppController {
  
  private final AppService appService;
  
  @PostMapping("/encryption/encrypt")
  public Mono<ResponseEntity<PayloadDto>> encrypt(@RequestBody Object payload) {
    return this.appService.encryptPayload(payload)
      .map(encryptedPayload -> new ResponseEntity<>(encryptedPayload,HttpStatus.OK));
  }
  
  @PostMapping("/encryption/decrypt")
  public Mono<ResponseEntity<Object>> encrypt(@RequestHeader(name = "key") String key,
    @RequestHeader(name = "vector") String vector, @RequestBody PayloadDto payload) {
    return this.appService.decryptPayload(payload,key,vector)
      .map(decryptedPayload -> new ResponseEntity<>(decryptedPayload, HttpStatus.OK));
  }
  
  
}
