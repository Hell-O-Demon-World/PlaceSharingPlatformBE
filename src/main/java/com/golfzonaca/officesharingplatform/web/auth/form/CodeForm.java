package com.golfzonaca.officesharingplatform.web.auth.form;

import lombok.Getter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Getter
public class CodeForm {
    @NotBlank(message = "이메일은 빈 값이 올 수 없습니다.")
    @Email
    private String email;
    @NotBlank(message = "인증번호는 빈 값이 올 수 없습니다.")
    @Size(min = 4, max = 4, message = "인증번호 길이는 4자리여야 합니다.")
    private String code;
}
