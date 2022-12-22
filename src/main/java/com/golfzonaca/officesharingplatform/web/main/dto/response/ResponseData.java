package com.golfzonaca.officesharingplatform.web.main.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ResponseData {
    private long id;
    private String name;
    private String address;
    private String mainInfo;

    @Override
    public String toString() {
        return "{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", address='" + address + '\'' +
                ", mainInfo='" + mainInfo + '\'' +
                '}';
    }
}
