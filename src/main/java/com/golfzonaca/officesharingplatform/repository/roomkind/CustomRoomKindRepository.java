package com.golfzonaca.officesharingplatform.repository.roomkind;

import com.golfzonaca.officesharingplatform.domain.RoomKind;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.exception.NonExistedRoomKindException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
@RequiredArgsConstructor
public class CustomRoomKindRepository implements RoomKindRepository {
    private final SpringDataJpaRoomKindRepository jpaRoomKindRepository;

    private final QueryRoomKindRepository queryRoomKindRepository;

    @Override
    public Long findIdByRoomType(String roomType) {
        return jpaRoomKindRepository.findIdByRoomTypeLike(roomType);
    }

    @Override
    public RoomKind findById(Long roomId) {
        return jpaRoomKindRepository.findById(roomId).orElseThrow(() -> new NonExistedRoomKindException("NonExistedRoomKindException::: 존재하지 않는 공간유형입니다."));
    }

    @Override
    public RoomKind findByRoomType(RoomType roomType) {
        return queryRoomKindRepository.findByRoomType(roomType).orElseThrow(() -> new NonExistedRoomKindException("NonExistedRoomKindException::: 존재하지 않는 공간유형입니다."));
    }

    @Override
    public List<RoomKind> findAll() {
        return jpaRoomKindRepository.findAll();
    }
}
