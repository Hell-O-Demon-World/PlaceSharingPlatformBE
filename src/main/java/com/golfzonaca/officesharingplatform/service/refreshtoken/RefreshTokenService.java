package com.golfzonaca.officesharingplatform.service.refreshtoken;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.golfzonaca.officesharingplatform.auth.token.EncodedToken;
import com.golfzonaca.officesharingplatform.domain.RefreshToken;

public interface RefreshTokenService {

    RefreshToken create(RefreshToken refreshToken);

    boolean existToken(Long userID);

    RefreshToken getRefreshToken(Long userId);

    void expire(EncodedToken encodedJwt) throws JsonProcessingException;
}
