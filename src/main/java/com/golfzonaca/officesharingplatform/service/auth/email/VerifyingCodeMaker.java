package com.golfzonaca.officesharingplatform.service.auth.email;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class VerifyingCodeMaker {
    private String code;

    public VerifyingCodeMaker(String code) throws NoSuchAlgorithmException {
        this.code = makeCode();
    }

    public static String makeCode() throws NoSuchAlgorithmException {
        int asciiStartNum = 48;
        int asciiEndNum = 90;
        int targetStringLength = 4;

        SecureRandom instanceStrong = SecureRandom.getInstanceStrong();
        String resultCode = instanceStrong.ints(asciiStartNum,asciiEndNum + 1)
                .filter(i -> (i <= 57 || i >= 65))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        return resultCode;
    }
}
