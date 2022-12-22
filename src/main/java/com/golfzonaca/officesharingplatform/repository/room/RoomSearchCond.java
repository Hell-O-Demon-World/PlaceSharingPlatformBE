package com.golfzonaca.officesharingplatform.repository.room;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoomSearchCond {
    private Long roomKindId;
    private Long placeId;
    private Integer totalNum;
}
