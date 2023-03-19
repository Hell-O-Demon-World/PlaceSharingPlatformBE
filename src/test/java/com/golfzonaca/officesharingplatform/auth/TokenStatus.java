package com.golfzonaca.officesharingplatform.auth;

import lombok.Getter;

@Getter
public enum TokenStatus {
    STATUS_NULL("Token is Null"), STATUS_REFRESH_TOKEN_EXPIRED("Login Again")
    , STATUS_ACCESS_TOKEN_EXPIRED("Expiration access token"), ;
    private String message;

    TokenStatus(String message) {
        this.message = message;
    }

}
