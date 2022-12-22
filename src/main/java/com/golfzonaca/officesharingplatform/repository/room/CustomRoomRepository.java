package com.golfzonaca.officesharingplatform.repository.room;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Room;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.exception.NonExistedRoomException;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
@RequiredArgsConstructor
public class CustomRoomRepository implements RoomRepository {
    private final SpringDataJpaRoomRepository jpaRoomRepository;
    private final QueryRoomRepository queryRoomRepository;

    @Override
    public List<Room> findAvailableRoomsByPlace(Place place) {
        return queryRoomRepository.findAvailableRoomsByPlace(place);
    }

    @Override
    public List<Room> findRoomByPlaceIdAndRoomKindId(Long placeId, Long roomKindId) {
        return findAll(RoomSearchCond.builder()
                .placeId(placeId)
                .roomKindId(roomKindId)
                .build());
    }

    @Override
    public List<Long> findRoomIdByPlaceIdAndRoomTypeId(Long placeId, Long roomKindId) {
        return queryRoomRepository.findIdAll(RoomSearchCond.builder()
                .placeId(placeId)
                .roomKindId(roomKindId)
                .build());
    }

    @Override
    public int countRoomQuantityByPlaceId(Long placeId, Long roomKindId) {
        return jpaRoomRepository.countRoomByPlaceIdAndRoomKindId(placeId, roomKindId);
    }

    @Override
    public List<Integer> findRoomTypeByPlaceId(Long placeId) {
        return null;
    }

    @Override
    public List<Room> findAll(RoomSearchCond cond) {
        return queryRoomRepository.findAll(cond);
    }

    @Override
    public List<Room> findRoomByPlaceAndRoomKind(Place place, RoomType selectedType) {
        return queryRoomRepository.findRoomByPlaceAndRoomKind(place, selectedType);
    }

    @Cacheable(cacheNames = "roomDataByPlaceAndType", sync = true, key = "#placeId+'&'+#selectedType")
    @Override
    public List<Room> findRoomByPlaceIdAndRoomType(Long placeId, RoomType selectedType) {
        return queryRoomRepository.findAllByPlaceIdAndRoomType(placeId, selectedType);
    }

    @Override
    public Room findById(Long resultRoomId) {
        return jpaRoomRepository.findById(resultRoomId).orElseThrow(() -> new NonExistedRoomException("NotExistRoomException::: 예약가능한 Room이 없습니다."));
    }

    @Override
    public List<Room> findByPlace(Place place) {
        return queryRoomRepository.findAllByPlace(place);
    }
}
