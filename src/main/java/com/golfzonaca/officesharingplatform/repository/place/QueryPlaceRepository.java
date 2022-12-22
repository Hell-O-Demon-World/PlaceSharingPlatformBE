package com.golfzonaca.officesharingplatform.repository.place;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.repository.place.dto.FilterData;
import com.golfzonaca.officesharingplatform.web.main.dto.request.RequestSearchData;
import com.querydsl.core.Tuple;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import javax.persistence.EntityManager;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QPlace.place;
import static com.golfzonaca.officesharingplatform.domain.QRoom.room;
import static com.golfzonaca.officesharingplatform.domain.QRoomKind.roomKind;

@Repository
@Transactional
public class QueryPlaceRepository {
    private final JPAQueryFactory query;

    public QueryPlaceRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public List<Place> findPlaces(RequestSearchData requestSearchData) {

        String searchWord = requestSearchData.getSearchWord();

        return query
                .selectFrom(place)
                .innerJoin(place.rooms, room)
                .innerJoin(room.roomKind, roomKind)
                .where(likeName(searchWord).or(likeAddress(Optional.of(searchWord))))
                .groupBy(place)
                .fetch();
    }

    public List<Place> filterPlaces(FilterData filterData) {

        return query
                .selectFrom(place)
                .join(place.rooms, room)
                .join(room.roomKind, roomKind)
                .where(likeCityOrSubCity(Optional.ofNullable(filterData.getCity()), Optional.ofNullable(filterData.getSubCity())), likeDay(Optional.ofNullable(filterData.getDay())), beforeStartTime(Optional.ofNullable(filterData.getStartTime())), afterEndTime(Optional.ofNullable(filterData.getEndTime())), likeRoomTypeCategory(Optional.ofNullable(filterData.getRoomTypeList())))
                .groupBy(place)
                .fetch();
    }

    public Optional<String> findOpenDayById(Long id) {
        return Optional.ofNullable(query
                .select(place.openDays)
                .from(place)
                .where(place.id.eq(id))
                .fetchFirst());
    }

    public Tuple findStartAndEndTimeById(Long id) {
        return query.select(place.placeStart, place.placeEnd)
                .from(place)
                .where(place.id.eq(id))
                .fetchFirst();
    }

    private BooleanExpression likeName(String name) {
        if (StringUtils.hasText(name)) {
            return place.placeName.contains(name);
        }
        return null;
    }

    private BooleanExpression likeAddress(Optional<String> address) {
        if (address.isPresent()) {
            return place.address.address.contains(address.get());
        }
        return null;
    }

    private BooleanExpression likeCityOrSubCity(Optional<String> city, Optional<String> subCity) {
        if (city.isPresent() && subCity.isEmpty()) {
            return place.address.address.like(city.get() + '%');
        } else if (city.isPresent()) {
            return place.address.address.like(city.get() + ' ' + subCity.get() + '%');
        }
        return null;
    }

    private BooleanExpression likeDay(Optional<String> day) {
        if (day.isPresent()) {
            return place.openDays.contains(day.get());
        }
        return null;
    }

    private BooleanExpression beforeStartTime(Optional<LocalTime> startTime) {
        if (startTime.isPresent()) {
            return place.placeStart.loe(startTime.get());
        }
        return null;
    }

    private BooleanExpression afterEndTime(Optional<LocalTime> endTime) {
        if (endTime.isPresent()) {
            return place.placeEnd.goe(endTime.get());
        }
        return null;
    }

    private BooleanExpression likeRoomTypeCategory(Optional<List<RoomType>> roomType) {
        if (roomType.isPresent()) {
            return room.roomKind.roomType.in(roomType.get());
        }
        return null;
    }

}