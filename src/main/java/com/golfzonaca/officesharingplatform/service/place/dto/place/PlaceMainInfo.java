package com.golfzonaca.officesharingplatform.service.place.dto.place;

import com.golfzonaca.officesharingplatform.service.place.dto.roomtype.RoomTypeResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class PlaceMainInfo {
    private String placeId;
    private String placeName;
    private String placePostalCode;
    private String placeAddress;
    private List<String> placeMainInfo;
    private List<String> placeImage;
    private String ratePoint;
    private String reviewQuantity;
    private String deskQuantity;
    private String meetingRoomQuantity;
    private String officeQuantity;
    private String placeDescription;
    private List<String> placeCloseDays;
    private String placeOpenTime;
    private String placeCloseTime;
    RoomTypeResponse roomTypeResponse;
}
