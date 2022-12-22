package com.golfzonaca.officesharingplatform.web.reservation.dto.process;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalTime;


@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ProcessReservationData {
    private String selectedType;
    private LocalDate startDate;
    private LocalDate endDate;
    private LocalTime startTime;
    private LocalTime endTime;
}
