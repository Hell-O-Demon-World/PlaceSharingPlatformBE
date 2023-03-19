package com.golfzonaca.officesharingplatform.auth.token;

import com.google.gson.JsonObject;
import lombok.Getter;

@Getter
public class ResponseJsonJwts {
    private JsonObject jsonJwt;

    public ResponseJsonJwts(EncodedToken encodedAccessToken, EncodedToken encodedRefreshToken) {
        this.jsonJwt = encodedTokensToJson(encodedAccessToken, encodedRefreshToken);
    }

    private JsonObject encodedTokensToJson(EncodedToken encodedAccessToken, EncodedToken encodedRefreshToken) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("accessToken", encodedAccessToken.getEncodedToken());
        jsonObject.addProperty("refreshToken", encodedRefreshToken.getEncodedToken());
        return jsonObject;
    }
}
