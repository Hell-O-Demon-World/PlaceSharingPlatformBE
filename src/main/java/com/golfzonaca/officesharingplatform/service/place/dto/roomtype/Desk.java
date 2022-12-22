package com.golfzonaca.officesharingplatform.service.place.dto.roomtype;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class Desk {
    private boolean exist;
    private Integer price;
    private List<String> images;
}
