package com.golfzonaca.officesharingplatform.domain.type;

public enum MileagePaymentReason {
    FULL_PAYMENT("선결제"), REFUND("환불"), USE_MILEAGE("마일리지 사용");
    private final String description;
    MileagePaymentReason(String description) {
        this.description = description;
    }
    public String getDescription() {
        return description;
    }

}
