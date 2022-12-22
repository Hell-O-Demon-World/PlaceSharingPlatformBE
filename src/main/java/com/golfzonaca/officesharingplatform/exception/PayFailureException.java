package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.BAD_REQUEST)
public class PayFailureException extends RuntimeException {
    public PayFailureException(String msg) {
        super(msg);
    }
}
