package com.golfzonaca.officesharingplatform.service.place.dto.roomtype;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.jetbrains.annotations.NotNull;

import java.util.List;

@Data
@AllArgsConstructor
public class Office implements Comparable<Office> {
    private String typeCode;
    private Integer price;
    private List<String> images;

    @Override
    public int compareTo(@NotNull Office o) {
        Integer o1 = Integer.parseInt(this.typeCode.replaceAll("[^0-9]", ""));
        Integer o2 = Integer.parseInt(o.typeCode.toString().replaceAll("[^0-9]", ""));
        return o1 - o2;
    }
}
