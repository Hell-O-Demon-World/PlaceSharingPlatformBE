package com.golfzonaca.officesharingplatform.repository.roomkind;

import com.golfzonaca.officesharingplatform.domain.RoomKind;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SpringDataJpaRoomKindRepository extends JpaRepository<RoomKind, Long> {

    @Query("select rk.id from RoomKind rk where rk.roomType=:roomType")
    Long findIdByRoomTypeLike(@Param("roomType") String roomType);
}
