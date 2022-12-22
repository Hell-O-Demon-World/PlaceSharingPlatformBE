package com.golfzonaca.officesharingplatform.web.formatter;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.Locale;

public class TimeFormatter {
    public static LocalDate toLocalDate(String day) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("uuuu-M-d");
        return LocalDate.parse(day, formatter);
    }

    public static LocalTime toLocalTime(String hour) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("H");
        return LocalTime.parse(hour, formatter);
    }

    public static LocalDateTime toLocalDateTime(String dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("uuuu-M-d H:m:s");
        return LocalDateTime.parse(dateTime, formatter);
    }

    public static String toDayOfTheWeek(LocalDate date) {
        return date.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.US);
    }
}
