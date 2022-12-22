package com.golfzonaca.officesharingplatform.domain.type;

import lombok.Getter;

@Getter
public enum ReservationStatus {
    PROGRESSING("예약 진행 중"), COMPLETED("예약 완료"), CANCELED("예약 취소");

    private String description;

    ReservationStatus(String description) {
        this.description = description;
    }
}