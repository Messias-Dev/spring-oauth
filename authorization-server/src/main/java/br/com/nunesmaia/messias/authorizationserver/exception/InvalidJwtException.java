package br.com.nunesmaia.messias.authorizationserver.exception;

public class InvalidJwtException extends Exception{

    public InvalidJwtException() {
        super("Invalid JWT");
    }
}
