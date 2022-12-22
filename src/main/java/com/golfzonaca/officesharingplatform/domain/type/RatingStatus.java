package com.golfzonaca.officesharingplatform.domain.type;

import lombok.Getter;

@Getter
public enum RatingStatus {
    YET("작성 불가"), WRITABLE("작성 가능"), WRITTEN("작성 완료");

    private final String description;

    RatingStatus(String description) {
        this.description = description;
    }
}
