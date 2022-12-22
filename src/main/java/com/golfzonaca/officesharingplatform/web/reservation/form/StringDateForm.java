package com.golfzonaca.officesharingplatform.web.reservation.form;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class StringDateForm {
    private static String year;
    private static String month;
    private static String day;

    public static LocalDate toLocalDate(String year, String month, String day) {
        String StringType = String.format("%s, %s, %s", year, month, day);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("uuuu, M, d");
        LocalDate resDate = LocalDate.parse(StringType, formatter);
        return resDate;
    }
}
