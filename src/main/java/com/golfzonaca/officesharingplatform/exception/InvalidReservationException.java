package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.BAD_REQUEST)
public class InvalidReservationException extends RuntimeException {
    public InvalidReservationException(String msg) {
        super(msg);
    }
}
