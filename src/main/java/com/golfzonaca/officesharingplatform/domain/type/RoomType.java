package com.golfzonaca.officesharingplatform.domain.type;

import com.golfzonaca.officesharingplatform.exception.RoomTypeErrorException;

public enum RoomType {
    DESK("데스크"), MEETINGROOM4("4인 회의실"), MEETINGROOM6("6인 회의실"), MEETINGROOM10("10인 회의실"), MEETINGROOM20("20인 회의실"), OFFICE20("20평 사무실"), OFFICE40("40평 사무실"), OFFICE70("70평 사무실"), OFFICE100("100평 사무실");

    private final String description;

    RoomType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description.toUpperCase();
    }

    public static RoomType getRoomType(String beforeRoomType) {
        int count = 0;
        for (RoomType room : RoomType.values()) {
            if (!beforeRoomType.toUpperCase().equals(room.name())) {
                count++;
            }
        }
        if (count == RoomType.values().length) {
            throw new RoomTypeErrorException("RoomType IO Exception::: Not Exist RoomType");
        }
        return RoomType.valueOf(beforeRoomType.toUpperCase());
    }
}
