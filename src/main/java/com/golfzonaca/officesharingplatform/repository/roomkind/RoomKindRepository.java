package com.golfzonaca.officesharingplatform.repository.roomkind;

import com.golfzonaca.officesharingplatform.domain.RoomKind;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;

import java.util.List;

public interface RoomKindRepository {
    Long findIdByRoomType(String roomType);

    RoomKind findById(Long roomId);

    RoomKind findByRoomType(RoomType roomType);

    List<RoomKind> findAll();
}
