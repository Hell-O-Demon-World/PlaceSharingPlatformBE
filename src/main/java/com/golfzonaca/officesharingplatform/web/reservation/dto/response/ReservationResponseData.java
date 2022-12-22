package com.golfzonaca.officesharingplatform.web.reservation.dto.response;

import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.domain.type.dateformat.DateTimeFormat;
import com.golfzonaca.officesharingplatform.service.reservation.TimeStates;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
public class ReservationResponseData {
    private RoomType productType;
    private boolean state;
    private DateTimeFormat date;
    private TimeStates timeStates;

}
