package com.golfzonaca.officesharingplatform.web.auth;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class VerifyingCodeMakerTest {
    private String code;

    @Test
    void makeCode() throws NoSuchAlgorithmException {
        int asciiStartNum = 48;
        int asciiEndNum = 90;
        int targetStringLength = 4;

        SecureRandom instanceStrong = SecureRandom.getInstanceStrong();
        String resultCode = instanceStrong.ints(asciiStartNum,asciiEndNum + 1)
                .filter(i -> (i <= 57 || i >= 65))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        System.out.println("resultCode = " + resultCode);
    }
}