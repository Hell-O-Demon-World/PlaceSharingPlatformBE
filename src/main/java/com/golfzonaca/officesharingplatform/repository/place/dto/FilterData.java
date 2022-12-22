package com.golfzonaca.officesharingplatform.repository.place.dto;

import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class FilterData {
    private String day;
    private LocalTime startTime;
    private LocalTime endTime;
    private String city;
    private String subCity;
    private List<RoomType> roomTypeList;
}
