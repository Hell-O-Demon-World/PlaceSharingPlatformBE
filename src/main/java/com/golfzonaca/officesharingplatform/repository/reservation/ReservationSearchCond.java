package com.golfzonaca.officesharingplatform.repository.reservation;

import com.golfzonaca.officesharingplatform.domain.type.ReservationStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.Optional;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ReservationSearchCond {
    private Long roomKindId;
    private Long userId;
    private Long roomId;
    private LocalDate resStartDate;
    private LocalTime resStartTime;
    private LocalDate resEndDate;
    private LocalTime resEndTime;
    private ReservationStatus reservationStatus;
}
