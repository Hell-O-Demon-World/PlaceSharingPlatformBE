package com.golfzonaca.officesharingplatform.repository.ratepoint;

import com.golfzonaca.officesharingplatform.domain.RatePoint;

public interface RatePointRepository {

    void update(RatePoint ratePoint, Float ratingScore);
}
