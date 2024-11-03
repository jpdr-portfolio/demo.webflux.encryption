package com.jpdr.apps.demo.webflux.encryption.exception;

public class MissingParameterException extends RuntimeException{
  public MissingParameterException(String parameterName){
    super("The parameter " + parameterName + " is null or missing in the application.yml file");
  }
}
