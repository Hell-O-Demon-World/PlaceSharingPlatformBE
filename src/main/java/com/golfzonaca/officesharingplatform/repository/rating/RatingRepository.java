package com.golfzonaca.officesharingplatform.repository.rating;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Rating;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.web.rating.dto.RatingUpdateData;

import java.util.List;

public interface RatingRepository {
    Rating save(Rating rating);

    Rating findById(long ratingId);

    void update(Rating rating, RatingUpdateData updateData);

    void delete(Rating rating);

    Long countByUser(User user);

    List<Rating> findAllByUserWithPagination(User user, Integer page);

    Integer countByPlace(Place place);

    List<Rating> findAllByPlaceWithPagination(Place place, Integer page);
}
