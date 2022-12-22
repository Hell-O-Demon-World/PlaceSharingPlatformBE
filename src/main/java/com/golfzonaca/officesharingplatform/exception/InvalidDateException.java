package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.NoSuchElementException;

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "error.room")
public class InvalidDateException extends NoSuchElementException {

    public InvalidDateException(String msg) {
        super(msg);
    }
}
