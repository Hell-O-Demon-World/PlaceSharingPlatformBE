package com.golfzonaca.officesharingplatform.repository.room;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Room;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.List;
import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QRoom.room;

@Slf4j
@Transactional
@Repository
public class QueryRoomRepository {
    private final JPAQueryFactory query;

    public QueryRoomRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    List<Long> findIdAll(RoomSearchCond cond) {
        log.info("Room findIdAll cond = {}", cond);
        Optional<Long> roomKindId = Optional.ofNullable(cond.getRoomKindId());
        Optional<Long> placeId = Optional.ofNullable(cond.getPlaceId());
        return query
                .select(room.id)
                .from(room)
                .where(eqRoomKindId(roomKindId), eqPlaceId(placeId))
                .fetch();
    }

    List<Room> findAll(RoomSearchCond cond) {
        log.info("Room findAll cond = {}", cond);
        Optional<Long> roomKindId = Optional.ofNullable(cond.getRoomKindId());
        Optional<Long> placeId = Optional.ofNullable(cond.getPlaceId());

        return query
                .select(room)
                .from(room)
                .where(eqRoomKindId(roomKindId), eqPlaceId(placeId))
                .fetch();
    }

    public List<Room> findRoomByPlaceAndRoomKind(Place place, RoomType selectedType) {
        log.info("Room findRoomByPlaceAndRoomKind");
        return query
                .selectFrom(room)
                .innerJoin(room.roomKind)
                .where(placeEq(place), roomTypeLike(selectedType))
                .fetch();
    }

    private BooleanExpression eqRoomKindId(Optional<Long> roomKindId) {
        if (roomKindId.isPresent()) {
            return room.roomKind.id.eq(roomKindId.get());
        }
        return null;
    }

    private BooleanExpression eqPlaceId(Optional<Long> placeId) {
        if (placeId.isPresent()) {
            return room.place.id.eq(placeId.get());
        }
        return null;
    }

    private BooleanExpression placeEq(Place place) {
        if (place != null) {
            return room.place.eq(place);
        }
        return null;
    }

    private BooleanExpression eqRoomType(RoomType roomType) {
        if (roomType != null) {
            return room.roomKind.roomType.eq(roomType);
        }
        return null;
    }

    private BooleanExpression roomTypeLike(RoomType selectedType) {
        if (selectedType != null) {
            return room.roomKind.roomType.eq(selectedType);
        }
        return null;
    }

    public List<Room> findAllByPlaceIdAndRoomType(Long id, RoomType roomType) {
        log.info("Room findAllByPlaceIdAndRoomType");
        Optional<Long> placeId = Optional.ofNullable(id);
        return query
                .select(room)
                .from(room)
                .innerJoin(room.roomKind)
                .where(eqPlaceId(placeId), eqRoomType(roomType))
                .fetch();
    }

    public List<Room> findAvailableRoomsByPlace(Place place) {
        return query
                .selectFrom(room)
                .where(room.place.eq(place), room.roomStatus.status.eq(true))
                .fetch();
    }

    public List<Room> findAllByPlace(Place place) {
        return query
                .selectFrom(room)
                .where(room.place.eq(place))
                .orderBy(room.id.asc(), room.roomKind.id.asc())
                .fetch();
    }
}
