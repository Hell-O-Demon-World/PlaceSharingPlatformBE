package com.golfzonaca.officesharingplatform.domain.type;

public enum AddInfoType {
    Wifi("와이파이"), Coffee("커피머신"), Parking("주차장"), Monitor("대형모니터");

    private final String description;

    AddInfoType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
