package com.golfzonaca.officesharingplatform.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.NoSuchElementException;

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "")
public class NonExistedMileageException extends NoSuchElementException {
    public NonExistedMileageException() {
    }
    public NonExistedMileageException(String msg) {
        super(msg);
    }
}
