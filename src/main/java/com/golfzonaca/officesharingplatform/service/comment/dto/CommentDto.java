package com.golfzonaca.officesharingplatform.service.comment.dto;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class CommentDto {
    private String writer;
    private String context;
    private String writtenDate;
    private String writtenTime;

    public void processingWrittenTime(String writtenTime) {
        this.writtenTime = writtenTime;
    }
}
