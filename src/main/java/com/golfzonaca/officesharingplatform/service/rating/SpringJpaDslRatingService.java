package com.golfzonaca.officesharingplatform.service.rating;

import com.golfzonaca.officesharingplatform.domain.*;
import com.golfzonaca.officesharingplatform.exception.MismatchInfoException;
import com.golfzonaca.officesharingplatform.repository.ratepoint.RatePointRepository;
import com.golfzonaca.officesharingplatform.repository.rating.RatingRepository;
import com.golfzonaca.officesharingplatform.repository.reservation.ReservationRepository;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import com.golfzonaca.officesharingplatform.web.rating.dto.RatingUpdateData;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.NoSuchElementException;

@Service
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslRatingService implements RatingService {
    private final RatingRepository ratingRepository;
    private final ReservationRepository reservationRepository;
    private final UserRepository userRepository;
    private final RatePointRepository ratePointRepository;

    @Override
    public void save(Long userId, Long reservationId, Float ratingScore, String ratingReview) {
        User user = userRepository.findById(userId);
        Reservation reservation = reservationRepository.findById(reservationId);
        if (user != reservation.getUser()) {
            throw new MismatchInfoException("회원 정보와 예약자 정보가 일치하지 않습니다.");
        }
        Rating rating = new Rating(reservation, ratingScore, ratingReview, LocalDateTime.now());
        Rating rate = ratingRepository.save(rating);
        Place place = rating.getReservation().getRoom().getPlace();
        if (place.getRatePoint().getRatingPoint() == 0) {
            ratePointRepository.update(place.getRatePoint(), rate.getRatingScore());
        } else {
            float resultRatingScore = (float) Math.round(place.getRatePoint().getRatingPoint() + rate.getRatingScore() / 2 * 10) / 10;
            ratePointRepository.update(place.getRatePoint(), resultRatingScore);
        }
    }

    @Override
    public Rating findById(long ratingId) {
        return ratingRepository.findById(ratingId);
    }

    @Override
    public void update(Long userId, long ratingId, RatingUpdateData updateData) {
        User user = userRepository.findById(userId);
        Rating rating = ratingRepository.findById(ratingId);
        if (user != rating.getReservation().getUser()) {
            throw new NoSuchElementException("회원 정보와 예약자 정보가 일치하지 않습니다.");
        }
        RatePoint findRatePoint = rating.getReservation().getRoom().getPlace().getRatePoint();
        float result = (findRatePoint.getRatingPoint() * 2 - rating.getRatingScore() + updateData.getRatingScore()) / 2;

        ratePointRepository.update(findRatePoint, (float) (Math.round(result*10)/10));
        ratingRepository.update(rating, updateData);
    }

    @Override
    public void delete(Long userId, long ratingId) {
        User user = userRepository.findById(userId);
        Rating rating = ratingRepository.findById(ratingId);
        if (user != rating.getReservation().getUser()) {
            ratingRepository.delete(rating);
            ratePointRepository.update(rating.getReservation().getRoom().getPlace().getRatePoint(), (rating.getReservation().getRoom().getPlace().getRatePoint().getRatingPoint() * 2 - rating.getRatingScore()) / 2);
        }
    }

}
