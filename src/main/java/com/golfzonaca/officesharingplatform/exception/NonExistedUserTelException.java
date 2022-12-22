package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.NoSuchElementException;

@ResponseStatus(code = HttpStatus.UNAUTHORIZED, reason = "error.user")
public class NonExistedUserTelException extends NoSuchElementException {
    public NonExistedUserTelException() {
    }

    public NonExistedUserTelException(String msg) {
        super(msg);
    }
}
