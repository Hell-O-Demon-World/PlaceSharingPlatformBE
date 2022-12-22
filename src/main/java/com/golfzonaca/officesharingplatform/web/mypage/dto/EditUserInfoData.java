package com.golfzonaca.officesharingplatform.web.mypage.dto;

import com.golfzonaca.officesharingplatform.annotation.PhoneNum;
import lombok.Getter;
import lombok.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.LinkedHashMap;
import java.util.Map;

@Getter
public class EditUserInfoData {
    @PhoneNum(message = "전화번호는 '-' 없이 숫자만 입력해주시기 바랍니다.")
    @Size(min = 9, max = 11, message = "전화번호의 길이는 최소 9자, 최대 11자 입니다.")
    private String tel;
    @NotNull(message = "직업은 Null일 수 없습니다.")
    @Size(max = 20, message = "직업명의 길이는 최대 20자 이내 입니다.")
    private String job;
    @NotNull(message = "선호 유형은 Null일 수 없습니다.")
    private Map<String, Boolean> preferType = new LinkedHashMap<>();
}
