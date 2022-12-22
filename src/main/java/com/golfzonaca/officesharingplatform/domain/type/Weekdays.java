package com.golfzonaca.officesharingplatform.domain.type;

public enum Weekdays {
    Mon(1), Tue(2), Wed(3), Thu(4), Fri(5), Sat(6), Sun(7);
    private final int description;

    Weekdays(int description) {
        this.description = description;
    }

    public int getDescription() {
        return description;
    }
}
