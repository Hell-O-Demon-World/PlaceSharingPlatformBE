package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.NoSuchElementException;

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "error.reservation")
public class NonExistedReservationException extends NoSuchElementException {
    public NonExistedReservationException(String s) {
        super(s);
    }
}
