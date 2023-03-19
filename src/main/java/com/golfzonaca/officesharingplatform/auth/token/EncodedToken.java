package com.golfzonaca.officesharingplatform.auth.token;

import lombok.Getter;
import org.springframework.security.jwt.Jwt;

@Getter
public class EncodedToken {
    private String encodedToken;

    public EncodedToken(Jwt token) {
        this.encodedToken = token.getEncoded();
    }

    public EncodedToken(String encodedToken){
        this.encodedToken = encodedToken;
    }

}
