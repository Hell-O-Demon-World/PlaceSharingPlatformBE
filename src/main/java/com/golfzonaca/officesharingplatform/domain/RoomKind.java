package com.golfzonaca.officesharingplatform.domain;

import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@Table(name = "ROOM_KIND", uniqueConstraints = {@UniqueConstraint(name = "ROOM_KIND", columnNames = {"ROOM_TYPE"})})
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class RoomKind {

    @Id
    private Long id;

    @Column(name = "ROOM_TYPE", nullable = false)
    @Enumerated(EnumType.STRING)
    private RoomType roomType;

    @Column(name = "PRICE", nullable = false)
    private int price;
}
