package com.golfzonaca.officesharingplatform.repository.ratepoint;

import com.golfzonaca.officesharingplatform.domain.RatePoint;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class SpringJpaDslRatePointRepository implements RatePointRepository {

    @Override
    public void update(RatePoint ratePoint, Float ratingScore) {
        ratePoint.UpdateRatePoint(ratingScore);
    }
}
