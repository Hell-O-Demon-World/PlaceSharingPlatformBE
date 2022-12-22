package com.golfzonaca.officesharingplatform.domain.type.dateformat;

import com.golfzonaca.officesharingplatform.service.reservation.TimeStates;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Month;
import java.util.List;

@Getter
@AllArgsConstructor
public class DateTimeFormat {
    private final Integer year;
    private final Integer month;
    private final Integer day;
    private final TimeStates timeStates;
    public static DateTimeFormat of(Integer year, Month month, Integer day, TimeStates timeStates) {
        return new DateTimeFormat(year, month.getValue(), day, timeStates);
    }
}
