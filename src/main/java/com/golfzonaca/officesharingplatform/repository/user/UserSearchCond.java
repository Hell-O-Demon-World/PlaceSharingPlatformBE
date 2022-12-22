package com.golfzonaca.officesharingplatform.repository.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSearchCond {
    private String name;
    private String mail;
    private String phoneNumber;
    private String job;
    private String userPlace;
}
