package com.golfzonaca.officesharingplatform.service.mypage.dto.usage;

import lombok.Builder;

@Builder
public class MyReservationList {
    private long reservationId;
    private String productType;
    private String placeName;
    private String reservationCompletedDate;
    private String reservationCompletedTime;
    private String reservationStartDate;
    private String reservationStartTime;
    private String reservationEndDate;
    private String reservationEndTime;
    private String usageStatus;
    private Boolean ratingStatus;
    private Boolean cancelStatus;
    private Boolean completeStatus;
    private String ratingStatusDescription;

}
