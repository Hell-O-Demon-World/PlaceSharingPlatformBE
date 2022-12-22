package com.golfzonaca.officesharingplatform.domain.type;

public enum DaysType {

    Mon("월요일"), Tue("화요일"), Wed("수요일"), Thu("목요일"), Fri("금요일"), Sat("토요일"), Sun("일요일");

    private final String description;

    DaysType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
