package com.golfzonaca.officesharingplatform.domain;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserData {
    private String userName;
    private String joinDate;
    private Long mileagePoint;
    private Integer totalReviewNumber;
}
