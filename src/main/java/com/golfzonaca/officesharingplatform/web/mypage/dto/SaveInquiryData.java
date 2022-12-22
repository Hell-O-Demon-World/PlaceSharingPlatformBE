package com.golfzonaca.officesharingplatform.web.mypage.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SaveInquiryData {
    @NotBlank
    private String title;
    @NotBlank
    private String question;
}
