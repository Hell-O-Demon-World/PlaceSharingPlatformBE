package com.golfzonaca.officesharingplatform.web.rating;

import com.golfzonaca.officesharingplatform.annotation.TokenUserId;
import com.golfzonaca.officesharingplatform.service.rating.RatingService;
import com.golfzonaca.officesharingplatform.web.rating.dto.RatingSaveData;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RatingController {

    private final RatingService ratingService;

    @PostMapping("/rating/new/{reservationId}")
    public String saveRating(@TokenUserId Long userId, @PathVariable Long reservationId, @Validated @RequestBody RatingSaveData ratingSaveData, BindingResult bindingResult) {
        Float ratingScore = ratingSaveData.getRatingScore();
        String ratingReview = ratingSaveData.getRatingReview();
        ratingService.save(userId, reservationId, ratingScore, ratingReview);
        return "ok";
    }

    @GetMapping("/{reservationId}/rating/{ratingId}")
    public String ratingDetail(@PathVariable Long reservationId, @PathVariable Long ratingId) {
        ratingService.findById(ratingId);
        return "ok";
    }
}
