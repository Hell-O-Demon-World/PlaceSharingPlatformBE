package com.golfzonaca.officesharingplatform.service.ratepoint;

import com.golfzonaca.officesharingplatform.domain.RatePoint;
import com.golfzonaca.officesharingplatform.repository.ratepoint.RatePointRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SpringJpaDslRatePointService implements RatePointService {
    private final RatePointRepository ratePointRepository;

    @Override
    public void update(RatePoint ratePoint, Float ratingScore) {
        ratePointRepository.update(ratePoint, ratingScore);
    }
}
