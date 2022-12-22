package com.golfzonaca.officesharingplatform.web.auth.form;

import lombok.Getter;

import java.security.NoSuchAlgorithmException;

@Getter
public class EmailForm {
    private String address;
    private final String title = "OfficeSharingPlatForm 인증 메일 입니다.";
    private String message;
    private String code;

    public void toEntity(String address, String code) throws NoSuchAlgorithmException {
        this.address = address;
        this.message = setMessage(code);
        this.code = code;

    }

    public String setMessage(String code) throws NoSuchAlgorithmException {
        String message = "";
        message += "인증번호는 " + code + "입니다. 회원가입 페이지로 돌아가서 올바르게 입력 해주세요";
        return message;
    }
}
