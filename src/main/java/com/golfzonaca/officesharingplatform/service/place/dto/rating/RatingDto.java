package com.golfzonaca.officesharingplatform.service.place.dto.rating;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class RatingDto {
    private Long ratingId;
    private String ratingScore;
    private String ratingWriter;
    private String writeDate;
    private String writeTime;
    private String usedRoomType;
    private String ratingContent;
    private String commentQuantity;
}
