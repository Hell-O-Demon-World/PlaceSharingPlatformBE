package com.golfzonaca.officesharingplatform.web.main.dto.request;

import com.golfzonaca.officesharingplatform.annotation.PhoneNum;
import lombok.Getter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
public class RequestFindIdForm {
    @NotBlank(message = "이름에 빈 문자나 공백 또는 Null 값이 들어갈 수 없습니다.")
    @Size(max = 20, message = "이름의 길이는 최대 20자 이내 입니다.")
    private String name;
    @PhoneNum(message = "전화번호는 '-' 없이 숫자만 입력해주시기 바랍니다.")
    @Size(min = 9, max = 11, message = "전화번호의 길이는 최소 9자, 최대 11자 입니다.")
    private String tel;
}
