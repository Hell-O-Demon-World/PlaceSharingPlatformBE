package com.golfzonaca.officesharingplatform.repository.room;

import com.golfzonaca.officesharingplatform.domain.Room;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface SpringDataJpaRoomRepository extends JpaRepository<Room, Long> {
    @Query("select count(r) from Room r where r.place.id=:placeId and r.roomKind.id=:roomKindId")
    int countRoomByPlaceIdAndRoomKindId(@Param("placeId") long placeId, @Param("roomKindId") long roomKindId);
}
