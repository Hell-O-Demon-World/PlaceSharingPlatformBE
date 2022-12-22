package com.golfzonaca.officesharingplatform.repository.room;


import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Room;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;

import java.util.List;

public interface RoomRepository {
    List<Room> findAvailableRoomsByPlace(Place place);

    List<Room> findRoomByPlaceIdAndRoomKindId(Long placeId, Long roomKindId);

    List<Long> findRoomIdByPlaceIdAndRoomTypeId(Long placeId, Long roomKindId);

    int countRoomQuantityByPlaceId(Long placeId, Long roomKindId);

    List<Integer> findRoomTypeByPlaceId(Long placeId);

    List<Room> findAll(RoomSearchCond cond);

    List<Room> findRoomByPlaceAndRoomKind(Place place, RoomType selectedType);

    List<Room> findRoomByPlaceIdAndRoomType(Long placeId, RoomType selectedType);

    Room findById(Long resultRoomId);

    List<Room> findByPlace(Place place);
}
