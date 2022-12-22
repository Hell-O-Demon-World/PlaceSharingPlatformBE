package com.golfzonaca.officesharingplatform.exception;

import java.util.NoSuchElementException;

public class UnavailablePlaceException extends NoSuchElementException {
    public UnavailablePlaceException(String s) {
        super(s);
    }
}
