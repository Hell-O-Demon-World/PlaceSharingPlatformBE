package com.golfzonaca.officesharingplatform.domain.type;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum FixStatus {
    FIXED("구매 확정"), UNFIXED("환불 가능"), CANCELED("취소");

    private final String description;
}
