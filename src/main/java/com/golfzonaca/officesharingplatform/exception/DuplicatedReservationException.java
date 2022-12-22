package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.NoSuchElementException;

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "error.room")
public class DuplicatedReservationException extends RuntimeException {
    public DuplicatedReservationException(String msg) {
        super(msg);
    }
}
