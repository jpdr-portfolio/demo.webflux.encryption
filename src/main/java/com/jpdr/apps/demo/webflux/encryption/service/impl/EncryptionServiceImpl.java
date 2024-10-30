package com.jpdr.apps.demo.webflux.encryption.service.impl;

import com.jpdr.apps.demo.webflux.encryption.exception.InitializationException;
import com.jpdr.apps.demo.webflux.encryption.service.EncryptionService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.function.Tuples;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class EncryptionServiceImpl implements EncryptionService {
  
  private SecureRandom secureRandom;
  
  @PostConstruct
  void postConstruct(){
    try{
      secureRandom = SecureRandom.getInstanceStrong();
    } catch (NoSuchAlgorithmException e) {
      throw new InitializationException(e);
    }
    
  }
  
  
  @Override
  public Mono<byte[]> getHeaderKeyBytes() {
    return getSecureBytes(KEY_SIZE);
  }
  
  @Override
  public Mono<byte[]> getHeaderVectorBytes() {
    return getSecureBytes(VECTOR_SIZE);
  }
  
  @Override
  public Mono<String> encryptAES(byte[] dataToEncrypt, SecretKey headerSecretKey, byte[] vectorBytes) {
    return Mono.just(
      Tuples.of(dataToEncrypt, headerSecretKey, new GCMParameterSpec(TAG_LENGTH_BIT, vectorBytes)))
      .flatMap(tuple -> {
        try{
          Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
          cipher.init(Cipher.ENCRYPT_MODE, tuple.getT2(), tuple.getT3());
          byte[] encryptedData = cipher.doFinal(dataToEncrypt);
          return Mono.just(Tuples.of(tuple.getT1(), encryptedData));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
          return Mono.error(e);
        }
      })
      .flatMap(tuple -> {
        String testData = Base64.getUrlEncoder().encodeToString(tuple.getT1());
        String encryptedDataBase64 = Base64.getUrlEncoder()
          .encodeToString(tuple.getT2())
          .split("=")[0]
          .substring(0, testData.length());
        String tag = Base64.getUrlEncoder()
          .encodeToString(tuple.getT2())
          .split("=")[0]
          .substring(testData.length());
        return Mono.just(encryptedDataBase64 + "." + tag);
      });
  }
  
  @Override
  public Mono<String> decryptAES(String encryptedDataBase64, String vectorBase64, String encryptedKeyBase64, String appPrivateKey) {
    return Mono.zip(
        Mono.just(encryptedDataBase64.split("\\.")),
        Mono.from(decryptRSAToGCM(encryptedKeyBase64, appPrivateKey)
            .map(decryptedKeyBytes -> new SecretKeySpec(decryptedKeyBytes, "AES"))),
        Mono.just(Base64.getDecoder().decode(vectorBase64))
          .map(decryptedVectorBytes -> new GCMParameterSpec(TAG_LENGTH_BIT, decryptedVectorBytes)))
      .flatMap(tuple -> {
        try{
          String encryptedDataPart = tuple.getT1()[0];
          String authTagPart = tuple.getT1()[1];
          byte[] encryptedDataBytes = Base64.getUrlDecoder().decode(encryptedDataPart);
          byte[] authTagBytes = Base64.getUrlDecoder().decode(authTagPart);
          byte[] cipherTagBytes = new byte[encryptedDataBytes.length + authTagBytes.length];
          System.arraycopy(encryptedDataBytes,0 , cipherTagBytes, 0, encryptedDataBytes.length);
          System.arraycopy(authTagBytes, 0, cipherTagBytes, encryptedDataBytes.length, authTagBytes.length );
          Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
          cipher.init(Cipher.DECRYPT_MODE, tuple.getT2() ,tuple.getT3());
          return Mono.just(cipher.doFinal(cipherTagBytes));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
          return Mono.error(e);
        }
      })
      .map(decryptedData -> new String(decryptedData, StandardCharsets.UTF_8));
  }
  
  @Override
  public Mono<String> encryptRSA(String dataToEncrypt, String appPublicKey) {
    return Mono.zip(
        Mono.just(dataToEncrypt),
        Mono.from(getPublicKey(appPublicKey)))
      .flatMap(tuple -> {
        try{
          Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
          cipher.init(Cipher.ENCRYPT_MODE, tuple.getT2());
          return Mono.just(cipher.doFinal(tuple.getT1().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 BadPaddingException | InvalidKeyException e) {
          return Mono.error(e);
        }
      })
      .map(Base64.getEncoder()::encode)
      .map(String::new);
  }
  
  
  private static Mono<byte[]> decryptRSAToGCM(String dataToDecrypt, String appPrivateKey){
    return Mono.zip(
        Mono.from(getPrivateKey(appPrivateKey)),
        Mono.just(Base64.getDecoder().decode(dataToDecrypt)))
      .flatMap(tuple -> {
        try{
          Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
          cipher.init(Cipher.DECRYPT_MODE, tuple.getT1());
          return Mono.just(cipher.doFinal(tuple.getT2()));
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 BadPaddingException | InvalidKeyException e) {
          return Mono.error(e);
        }
      })
      .map(Base64.getDecoder()::decode);
  }
  
  private Mono<byte[]> getSecureBytes(int arraySize){
    return Mono.fromCallable( () -> {
      byte[] randomBytes = new byte[arraySize];
      secureRandom.nextBytes(randomBytes);
      return randomBytes;
      })
      .subscribeOn(Schedulers.boundedElastic());
  }
  

  
  
  public static Mono<PublicKey> getPublicKey(String publicKey){
    return Mono.just(publicKey)
      .map(Base64.getDecoder()::decode)
      .map(X509EncodedKeySpec::new)
      .flatMap(x509EncodedKeySpec -> {
        try{
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          return Mono.just(keyFactory.generatePublic(x509EncodedKeySpec));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
          return Mono.error(e);
        }
      });
  }
  
  public static Mono<PrivateKey> getPrivateKey(String privateKey){
    return Mono.just(privateKey)
      .map(Base64.getDecoder()::decode)
      .map(PKCS8EncodedKeySpec::new)
      .flatMap(pkcs8EncodedKeySpec -> {
        try {
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          return Mono.just(keyFactory.generatePrivate(pkcs8EncodedKeySpec));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
          return Mono.error(e);
        }
      });
  }
  

  
}
