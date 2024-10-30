package com.jpdr.apps.demo.webflux.encryption.service;

import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;

public interface EncryptionService {
  
  int KEY_SIZE = 32;
  int VECTOR_SIZE = 16;
  String CIPHER_ALGORITHM = "RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING";
  String AES_ALGORITHM = "AES/GCM/NoPadding";
  int TAG_LENGTH_BIT = 128;
  
  Mono<byte[]> getHeaderKeyBytes();
  Mono<byte[]> getHeaderVectorBytes();
  Mono<String> encryptAES(byte[] dataToEncrypt, SecretKey headerSecretKey, byte[] vectorBytes);
  Mono<String> decryptAES(String encryptedDataBase64, String vectorBase64, String encryptedKeyBase64, String appPrivateKey);
  Mono<String> encryptRSA(String dataToEncrypt, String appPublicKey);
}
