package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.NoSuchElementException;

@ResponseStatus(code = HttpStatus.UNAUTHORIZED, reason = "error.user")
public class NonExistedUserNameException extends NoSuchElementException {
    public NonExistedUserNameException() {
    }

    public NonExistedUserNameException(String msg) {
        super(msg);
    }
}
