package com.golfzonaca.officesharingplatform.repository.rating;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Rating;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.exception.NonExistedRatingException;
import com.golfzonaca.officesharingplatform.web.rating.dto.RatingUpdateData;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslRatingRepository implements RatingRepository {
    private final SpringJpaRatingRepository jpaRepository;
    private final QueryRatingRepository queryRepository;

    @Override
    public Rating save(Rating rating) {
        return jpaRepository.save(rating);
    }

    @Override
    public Rating findById(long ratingId) {
        return jpaRepository.findById(ratingId).orElseThrow(NonExistedRatingException::new);
    }

    @Override
    public void update(Rating rating, RatingUpdateData updateData) {
        rating.UpdateRating(updateData.getRatingScore(), updateData.getRatingReview());
    }

    @Override
    public void delete(Rating rating) {
        jpaRepository.delete(rating);
    }

    @Override
    public Long countByUser(User user) {
        return queryRepository.countByUser(user);
    }

    @Override
    public List<Rating> findAllByUserWithPagination(User user, Integer page) {
        return queryRepository.findAllByUserWithPagination(user, page);
    }

    @Override
    public Integer countByPlace(Place place) {
        return jpaRepository.countByPlace(place.getId()).size();
    }

    @Override
    public List<Rating> findAllByPlaceWithPagination(Place place, Integer page) {
        return jpaRepository.findAllByPlaceWithPagination(place.getId(), page - 1);
    }
}
