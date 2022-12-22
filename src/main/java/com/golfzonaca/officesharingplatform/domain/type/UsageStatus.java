package com.golfzonaca.officesharingplatform.domain.type;

import lombok.Getter;

@Getter
public enum UsageStatus {
    UNFIXED("예약 진행 중"), BEFORE("이용 전"), NOW("이용 중"), AFTER("이용 완료"), CANCELED("예약 취소");

    private final String description;

    UsageStatus(String description) {
        this.description = description;
    }
}
