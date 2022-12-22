package com.golfzonaca.officesharingplatform.service.mypage.dto.edituserinfo;

import lombok.AllArgsConstructor;

import java.util.Map;

@AllArgsConstructor
public class EditUserInfo {
    private String tel;
    private String job;
    private Map<String, Boolean> preferType;
}
