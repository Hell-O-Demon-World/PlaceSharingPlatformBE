package com.golfzonaca.officesharingplatform.domain.type;

public enum PayType {
    DEPOSIT("보증금 결제"), BALANCE("후결제"), FULL_PAYMENT("선결제");
    private final String description;

    PayType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
