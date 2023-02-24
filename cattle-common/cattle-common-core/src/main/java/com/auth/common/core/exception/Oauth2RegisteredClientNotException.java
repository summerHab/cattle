package com.auth.common.core.exception;


import lombok.NoArgsConstructor;

@NoArgsConstructor
public class Oauth2RegisteredClientNotException extends RuntimeException{



    public Oauth2RegisteredClientNotException(String message) {
        super(message);
    }

    public Oauth2RegisteredClientNotException(String message, Throwable cause) {
        super(message, cause);
    }

    public Oauth2RegisteredClientNotException(Throwable cause) {
        super(cause);
    }

    protected Oauth2RegisteredClientNotException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
