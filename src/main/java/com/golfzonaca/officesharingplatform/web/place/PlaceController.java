package com.golfzonaca.officesharingplatform.web.place;

import com.golfzonaca.officesharingplatform.service.place.PlaceService;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class PlaceController {
    private final PlaceService placeService;

    @GetMapping("places/{placeId}")
    public Map<String, JsonObject> placeDetailsInfo(@PathVariable long placeId) {
        return placeService.getPlaceInfo(placeId);
    }

    @GetMapping("places/{placeId}/review")
    public Map<String, JsonObject> reviewData(@PathVariable Long placeId, @RequestParam Integer page) {
        return placeService.getReviewData(placeId, page);
    }

    @GetMapping("places/{placeId}/{reviewId}")
    public Map<String, JsonObject> commentData(@PathVariable Long placeId, @PathVariable Long reviewId, @RequestParam Integer page) {
        return placeService.getCommentData(reviewId, page);
    }
}