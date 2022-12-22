package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.NoSuchElementException;

@ResponseStatus(code = HttpStatus.UNAUTHORIZED, reason = "error.user")
public class NonExistedUserException extends NoSuchElementException {
    public NonExistedUserException() {
    }

    public NonExistedUserException(String msg) {
        super(msg);
    }
}
