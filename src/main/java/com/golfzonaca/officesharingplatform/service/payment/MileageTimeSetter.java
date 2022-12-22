package com.golfzonaca.officesharingplatform.service.payment;


import java.time.LocalDateTime;

public class MileageTimeSetter {
    private static final int MAX_EXPIRED_YEARS = 5;
    public static LocalDateTime currentDateTime() {
        return LocalDateTime.now();
    }
    public static LocalDateTime expiredDateTime() {
        return LocalDateTime.now().plusYears(MAX_EXPIRED_YEARS);
    }
}
