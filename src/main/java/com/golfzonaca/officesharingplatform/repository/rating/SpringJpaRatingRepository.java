package com.golfzonaca.officesharingplatform.repository.rating;

import com.golfzonaca.officesharingplatform.domain.Rating;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SpringJpaRatingRepository extends JpaRepository<Rating, Long> {
    @Query(value = "select rating.ID, rating.RATING_REVIEW, rating.RATING_SCORE, rating.RATING_TIME, rating.RESERVATION_ID from rating join reservation res on res.ID = rating.RESERVATION_ID join room on res.ROOM_ID = room.ID join place p on room.PLACE_ID = p.ID WHERE p.id = :placeId ORDER BY rating.RATING_TIME DESC", nativeQuery = true)
    List<Rating> countByPlace(@Param("placeId") Long placeId);

    @Query(value = "select rating.ID, rating.RATING_REVIEW, rating.RATING_SCORE, rating.RATING_TIME, rating.RESERVATION_ID from rating join reservation res on res.ID = rating.RESERVATION_ID join room on res.ROOM_ID = room.ID join place p on room.PLACE_ID = p.ID WHERE p.id = :placeId ORDER BY rating.RATING_TIME DESC limit :page,4", nativeQuery = true)
    List<Rating> findAllByPlaceWithPagination(@Param("placeId") Long placeId, @Param("page") Integer page);
}
