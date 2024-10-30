package com.jpdr.apps.demo.webflux.encryption.exception;

public class InitializationException extends RuntimeException{
  public InitializationException(Throwable ex){
    super("An error occurred while initializing the service.", ex);
  }
}
