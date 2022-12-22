package com.golfzonaca.officesharingplatform.service.place.dto.roomtype;

import lombok.Getter;

import java.util.SortedSet;

@Getter
public class RoomTypeResponse {
    private Desk desk;
    private SortedSet<MeetingRoom> meetingRoom;
    private SortedSet<Office> office;

    public void toEntity(Desk desk, SortedSet<MeetingRoom> meetingRoom, SortedSet<Office> office) {
        this.desk = desk;
        this.meetingRoom = meetingRoom;
        this.office = office;
    }
}
