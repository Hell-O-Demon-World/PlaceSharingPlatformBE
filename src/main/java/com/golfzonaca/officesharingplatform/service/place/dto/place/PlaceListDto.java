package com.golfzonaca.officesharingplatform.service.place.dto.place;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;
import java.util.Map;

@Getter
@AllArgsConstructor
public class PlaceListDto {
    List<String> placeImages;
    String placeId;
    String placeName;
    String ratingPoint;
    String address;
    List<String> placeInfo;
    String placeDescription;
    List<String> closeDays;
    String openTime;
    String closeTime;
    Map<String, String> roomInfo;
}
