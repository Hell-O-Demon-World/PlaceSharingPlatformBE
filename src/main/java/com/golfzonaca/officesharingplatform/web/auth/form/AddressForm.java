package com.golfzonaca.officesharingplatform.web.auth.form;

import lombok.Getter;

import javax.validation.constraints.Email;

@Getter
public class AddressForm {
    @Email
    private String address;
}
