package com.golfzonaca.officesharingplatform.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@Table(name = "roomstatus", uniqueConstraints = {@UniqueConstraint(name = "RoomStatus", columnNames = {"ROOM_ID"})})
@NoArgsConstructor
public class RoomStatus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "ROOM_ID")
    private Room room;

    @Column(name = "STATUS")
    private Boolean status;

    @Builder
    public RoomStatus(Room room, Boolean status) {
        this.room = room;
        this.status = status;
    }

    public void updateStatus(Boolean status) {
        this.status = status;
    }
}