package com.golfzonaca.officesharingplatform.service.mypage.dto.qna;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class QuestionData {
    private Long inquiryId;
    private String inquiryTitle;
    private String inquiryContext;
    private String writtenDate;
    private String writtenTime;
    private Boolean processingStatus;
}
