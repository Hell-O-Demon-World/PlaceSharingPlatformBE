package com.golfzonaca.officesharingplatform.repository.reservation;


import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Reservation;
import com.golfzonaca.officesharingplatform.domain.Room;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

public interface ReservationRepository {
    Reservation save(Reservation reservation);

    List<Reservation> findRecentDataByUserWithPagination(User user, Integer page, LocalDate date);

    List<Reservation> findAllByUserWithPagination(User user, Integer page);

    Optional<Reservation> findInDateByPlaceIdAndRoomTypeAndDate(Long placeId, RoomType roomType, LocalTime date);

    List<Reservation> findResByPlaceIdAndRoomKindId(long roomTypeId, LocalDate resStartDate, LocalDate resEndDate);

    void delete(Reservation reservation);

    List<Reservation> findAll(ReservationSearchCond cond);

    boolean findInResValid(User user, LocalDate startDate, LocalTime startTime, LocalDate endDate, LocalTime endTime);

    List<Reservation> findResByRoomKindAndDateTime(RoomType selectedType, LocalDate startDate, LocalTime startTime, LocalDate endDate, LocalTime endTime);

    Optional<Reservation> findByPlaceIdAndRoomTypeAndDate(Long placeId, RoomType roomType, LocalDate date);

    Reservation findById(Long reservationId);

    List<Reservation> findAllLimit(ReservationSearchCond cond, Integer maxNum);

    List<Reservation> findByUserAndDateTime(User user, LocalDate date, LocalTime time);

    List<Room> findByPlaceAndRoomKindAndStartDateAndEndDate(Place place, RoomType selectedType, LocalDate date, LocalDate endDate);

    Reservation findByIdAndUserID(long reservationId, Long userId);

    List<Reservation> findAllByPlaceIdAndRoomTypeAndDate(Long placeId, RoomType roomType, LocalDate date);
}
