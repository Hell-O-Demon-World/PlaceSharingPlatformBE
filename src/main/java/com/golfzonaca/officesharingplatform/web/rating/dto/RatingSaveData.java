package com.golfzonaca.officesharingplatform.web.rating.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.NotBlank;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RatingSaveData {
    @Range(min = 1, max = 5)
    private Float ratingScore;
    @NotBlank
    private String ratingReview;
}
