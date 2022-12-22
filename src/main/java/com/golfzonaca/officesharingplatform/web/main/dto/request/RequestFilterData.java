package com.golfzonaca.officesharingplatform.web.main.dto.request;

import com.golfzonaca.officesharingplatform.annotation.RequestFilterDataNotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@RequestFilterDataNotBlank(day = "day", startTime = "startTime", endTime = "endTime", city = "city", subCity = "subCity", type = "type")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RequestFilterData {
    private String day;
    private String startTime;
    private String endTime;
    private String city;
    private String subCity;
    private String type;
}