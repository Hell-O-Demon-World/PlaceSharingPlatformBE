package com.golfzonaca.officesharingplatform.repository.reservation;

import com.golfzonaca.officesharingplatform.domain.*;
import com.golfzonaca.officesharingplatform.domain.type.FixStatus;
import com.golfzonaca.officesharingplatform.domain.type.ReservationStatus;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QReservation.reservation;


@Slf4j
@Transactional
@Repository
public class QueryReservationRepository {
    private final JPAQueryFactory query;

    public QueryReservationRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    List<Reservation> findAll(ReservationSearchCond cond) {
        log.info("Reservation findAll cond = {}", cond);
        Optional<Long> userId = Optional.ofNullable(cond.getUserId());
        Optional<Long> roomId = Optional.ofNullable(cond.getRoomId());
        Optional<LocalTime> resStartTime = Optional.ofNullable(cond.getResStartTime());
        Optional<LocalDate> resStartDate = Optional.ofNullable(cond.getResStartDate());
        Optional<LocalTime> resEndTime = Optional.ofNullable(cond.getResEndTime());
        Optional<LocalDate> resEndDate = Optional.ofNullable(cond.getResEndDate());

        return query
                .selectFrom(reservation)
                .where(eqUserId(userId), eqRoomId(roomId), eqResStartTime(resStartTime), eqResStartDate(resStartDate)
                        , eqResEndTime(resEndTime), eqResEndDate(resEndDate))
                .fetch();
    }

    Optional<Reservation> findFirstByPlaceIdAndRoomTypeAndDate(Long placeId, RoomType roomType, LocalDate date) {
        Optional<RoomType> optionalRoomType = Optional.ofNullable(roomType);
        Optional<LocalDate> optionalLocalDate = Optional.ofNullable(date);
        return Optional.ofNullable(query
                .select(reservation)
                .from(reservation)
                .innerJoin(reservation.room.place)
                .innerJoin(reservation.room.roomKind)
                .where(reservation.room.place.id.eq(placeId), reservation.fixStatus.eq(FixStatus.FIXED), eqRoomType(optionalRoomType), betweenStartDateAndEndDate(optionalLocalDate))
                .fetchFirst());
    }

    Optional<Reservation> findInTimeByPlaceAndRoomTypeAndDate(Long placeId, RoomType roomType, LocalTime time) {
        Optional<RoomType> optionalRoomType = Optional.ofNullable(roomType);
        return Optional.ofNullable(
                query.select(reservation)
                        .from(reservation)
                        .innerJoin(reservation.room.place)
                        .innerJoin(reservation.room.roomKind)
                        .where(reservation.room.place.id.eq(placeId), eqRoomType(optionalRoomType)
                                , reservation.resStartTime.loe(time).and(reservation.resEndTime.after(time)))
                        .fetchFirst());
    }

    List<Reservation> findAllLimit(ReservationSearchCond cond, Integer maxNum) {
        log.info("Reservation findAllLimit cond = {}, maxNum = {}", cond, maxNum);
        Optional<Long> userId = Optional.ofNullable(cond.getUserId());
        Optional<Long> roomId = Optional.ofNullable(cond.getRoomId());
        Optional<LocalTime> resStartTime = Optional.ofNullable(cond.getResStartTime());
        Optional<LocalDate> resStartDate = Optional.ofNullable(cond.getResStartDate());
        Optional<LocalTime> resEndTime = Optional.ofNullable(cond.getResEndTime());
        Optional<LocalDate> resEndDate = Optional.ofNullable(cond.getResEndDate());

        return query
                .selectFrom(reservation)
                .innerJoin(reservation.user)
                .innerJoin(reservation.room)
                .where(eqUserId(userId), eqRoomId(roomId), eqResStartTime(resStartTime), eqResStartDate(resStartDate)
                        , eqResEndTime(resEndTime), eqResEndDate(resEndDate))
                .limit(maxNum)
                .fetch();
    }

    public Optional<Reservation> findInResValid(User user, LocalDate startDate, LocalTime startTime, LocalDate endDate, LocalTime endTime) {
        return Optional.ofNullable(query
                .selectFrom(reservation)
                .where(userEquals(user), reservation.status.ne(ReservationStatus.CANCELED), reservation.status.ne(ReservationStatus.PROGRESSING), reservation.resStartDate.eq(startDate), reservation.resEndDate.eq(endDate),
                        (reservation.resStartTime.loe(startTime).and(reservation.resEndTime.after(startTime)))
                                .or(reservation.resStartTime.after(startTime).and(reservation.resStartTime.before(endTime)))
                )
                .fetchFirst());
    }

    public Optional<Reservation> findResThatDay(User user, RoomType roomType, LocalDate startDate, LocalDate endDate) {
        return Optional.ofNullable(query
                .selectFrom(reservation)
                .where(userEquals(user), reservation.room.roomKind.roomType.eq(roomType), reservation.status.ne(ReservationStatus.CANCELED), reservation.status.ne(ReservationStatus.PROGRESSING),
                        (reservation.resStartDate.loe(startDate).and(reservation.resEndDate.after(startDate)))
                                .or(reservation.resStartDate.after(startDate).and(reservation.resStartDate.before(startDate))))
                .fetchFirst());
    }

    public List<Reservation> findResByRoomKindAndDateTime(RoomType selectedType, LocalDate startDate, LocalTime startTime
            , LocalDate endDate, LocalTime endTime) {
        return query
                .selectFrom(reservation)
                .innerJoin(reservation.room.roomKind)
                .where(roomTypeLike(selectedType), startDateEquals(startDate), startTimeLoe(startTime), endDateEquals(endDate), endTimeGoe(endTime))
                .fetch();
    }

    public List<Reservation> findAllByPlaceIdAndRoomTypeAndDate(Long placeId, RoomType roomType, LocalDate date) {
        Optional<RoomType> optionalRoomType = Optional.ofNullable(roomType);
        Optional<LocalDate> optionalLocalDate = Optional.ofNullable(date);
        return query
                .selectFrom(reservation)
                .innerJoin(reservation.room.place)
                .innerJoin(reservation.room.roomKind)
                .where(reservation.room.place.id.eq(placeId), reservation.fixStatus.ne(FixStatus.CANCELED), eqRoomType(optionalRoomType), betweenStartDateAndEndDate(optionalLocalDate))
                .fetch();
    }

    public List<Reservation> findRecentDataByUserWithPagination(User user, Integer page, LocalDate date) {
        return query
                .selectFrom(reservation)
                .innerJoin(reservation.user)
                .where(reservation.user.eq(user), startDateGoe(date), startTimeGt(LocalTime.now()), reservation.status.eq(ReservationStatus.COMPLETED))
                .orderBy(reservation.resStartDate.asc(), reservation.resStartTime.asc())
                .offset(8L * (page - 1))
                .limit(8)
                .fetch();
    }

    public List<Reservation> findAllByUserWithPagination(User user, Integer page) {
        return query
                .selectFrom(reservation)
                .innerJoin(reservation.user)
                .where(reservation.user.eq(user))
                .orderBy(reservation.resStartDate.desc(), reservation.resStartTime.desc())
                .offset(8L * (page - 1))
                .limit(8)
                .fetch();
    }

    public List<Reservation> findByUserAndDateTime(User user, LocalDate date, LocalTime time) {
        return query
                .selectFrom(reservation)
                .innerJoin(reservation.user)
                .where(reservation.user.eq(user), startDateEquals(date), startTimeLoe(time), endTimeGt(time), reservation.status.eq(ReservationStatus.COMPLETED))
                .orderBy(reservation.resStartTime.asc())
                .fetch();
    }

    public Optional<Reservation> findByUserAndRoom(User user, Room room) {
        if (user != null && room != null) {
            return Optional.ofNullable(query
                    .selectFrom(reservation)
                    .where(userEquals(user), roomEquals(room))
                    .fetchOne());
        }
        return null;
    }

    private BooleanExpression userEquals(User user) {
        if (user != null) {
            return reservation.user.eq(user);
        }
        return null;
    }

    private BooleanExpression PlaceEquals(Place place) {
        if (place != null) {
            return reservation.room.place.eq(place);
        }
        return null;
    }

    private BooleanExpression startDateGoe(LocalDate date) {
        if (date != null) {
            return reservation.resStartDate.goe(date);
        }
        return null;
    }

    private BooleanExpression startDateEquals(LocalDate date) {
        if (date != null) {
            return reservation.resStartDate.eq(date);
        }
        return null;
    }

    private BooleanExpression endDateEquals(LocalDate date) {
        if (date != null) {
            return reservation.resEndDate.eq(date);
        }
        return null;
    }

    private BooleanExpression startTimeLoe(LocalTime time) {
        if (time != null) {
            return reservation.resStartTime.loe(time);
        }
        return null;
    }

    private BooleanExpression endTimeGt(LocalTime time) {
        if (time != null) {
            return reservation.resEndTime.gt(time);
        }
        return null;
    }

    private BooleanExpression startTimeGt(LocalTime time) {
        if (time != null) {
            return reservation.resStartTime.gt(time);
        }
        return null;
    }

    private BooleanExpression startTimeLt(LocalTime time) {
        if (time != null) {
            return reservation.resStartTime.lt(time);
        }
        return null;
    }

    private BooleanExpression eqUserId(Optional<Long> userId) {
        if (userId.isPresent()) {
            return reservation.user.id.eq(userId.get());
        }
        return null;
    }

    private BooleanExpression eqRoomId(Optional<Long> roomId) {
        if (roomId.isPresent()) {
            return reservation.room.id.eq(roomId.get());
        }
        return null;
    }

    private BooleanExpression eqRoomKindId(Optional<Long> roomKindId) {
        if (roomKindId.isPresent()) {
            return reservation.room.roomKind.id.eq(roomKindId.get());
        }
        return null;
    }

    private BooleanExpression eqResStartTime(Optional<LocalTime> resStartTime) {
        if (resStartTime.isPresent()) {
            return reservation.resStartTime.eq(resStartTime.get());
        }
        return null;
    }

    private BooleanExpression eqResStartDate(Optional<LocalDate> resStartDate) {
        if (resStartDate.isPresent()) {
            return reservation.resStartDate.eq(resStartDate.get());
        }
        return null;
    }

    private BooleanExpression betweenStartDateAndEndDate(Optional<LocalDate> resDate) {
        if (resDate.isPresent()) {
            return reservation.resStartDate.loe(resDate.get()).and(reservation.resEndDate.goe(resDate.get()));
        }
        return null;
    }

    private BooleanExpression betweenStartTimeAndEndTime(Optional<LocalTime> localTime) {
        if (localTime.isPresent()) {
            LocalTime localTime1 = localTime.get();
            return reservation.resStartTime.after(localTime.get()).and(reservation.resEndTime.before(localTime1));
        }
        return null;
    }

    private BooleanExpression eqResEndTime(Optional<LocalTime> resEndTime) {
        if (resEndTime.isPresent()) {
            return reservation.resEndTime.eq(resEndTime.get());
        }
        return null;
    }

    private BooleanExpression eqResEndDate(Optional<LocalDate> resEndDate) {
        if (resEndDate.isPresent()) {
            return reservation.resEndDate.eq(resEndDate.get());
        }
        return null;
    }

    private BooleanExpression roomTypeLike(RoomType selectedType) {
        if (selectedType != null) {
            return reservation.room.roomKind.roomType.eq(selectedType);
        }
        return null;
    }

    private BooleanExpression endTimeGoe(LocalTime endTime) {
        if (endTime != null) {
            return reservation.resEndTime.goe(endTime);
        }
        return null;
    }

    private BooleanExpression eqRoomType(Optional<RoomType> optionalRoomType) {
        if (optionalRoomType.isPresent()) {
            return reservation.room.roomKind.roomType.eq(optionalRoomType.get());
        }
        return null;
    }


    private BooleanExpression roomEquals(Room room) {
        if (room != null) {
            return QRoom.room.eq(room);
        }
        return null;
    }

    public List<Room> findAllRoomByPlaceAndRoomKindAndStartDateAndEndDate(Place place, RoomType selectedType, LocalDate startDate, LocalDate endDate) {
        return query.select(reservation.room)
                .from(reservation)
                .where(reservation.room.place.eq(place), reservation.room.roomKind.roomType.eq(selectedType),
                        reservation.resStartDate.between(startDate, endDate.minusDays(1)).or(reservation.resEndDate.loe(endDate).and(reservation.resEndDate.gt(startDate))))
//                .or(reservation.resEndDate.between(startDate, endDate.minusDays(1))))
                .fetch();
    }
}
