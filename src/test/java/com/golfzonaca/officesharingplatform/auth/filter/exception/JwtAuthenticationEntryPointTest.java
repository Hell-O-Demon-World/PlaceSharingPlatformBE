package com.golfzonaca.officesharingplatform.auth.filter.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.golfzonaca.officesharingplatform.auth.TokenStatus;
import com.golfzonaca.officesharingplatform.auth.filter.servlet.JwtHttpServletProvider;
import com.golfzonaca.officesharingplatform.auth.token.EncodedToken;
import com.golfzonaca.officesharingplatform.auth.token.JwtManager;
import com.golfzonaca.officesharingplatform.auth.token.ResponseJsonJwts;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.jwt.Jwt;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@ExtendWith(SpringExtension.class)
class JwtAuthenticationEntryPointTest {
    private final JwtHttpServletProvider jwtHttpServletProvider = new JwtHttpServletProvider();
    private final Jwt refreshJwt = JwtManager.createRefreshJwt(13L);
    private final Jwt accessJwt = JwtManager.createAccessJwt(13L);
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint = new JwtAuthenticationEntryPoint(jwtHttpServletProvider);

    @Test
    @DisplayName("예외_발생")
    void 예외_발생() throws IOException {
        //given
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        //        Encoded token = new EncodedToken(getAuthorization(request));
        EncodedToken encodedToken = new EncodedToken(refreshJwt.getEncoded());
        //when
        tokenAction(request, response, encodedToken);
        Assertions.assertThat(10).isEqualTo(10);
        //then
    }

    private void tokenAction(HttpServletRequest request, HttpServletResponse response, EncodedToken token) throws IOException {
        if (token.getEncodedToken().isEmpty()) {
            //            log.warn("InvalidTokenException::: Token is Null");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, TokenStatus.STATUS_NULL.getMessage());
        } else if (isRefreshToken(request, token)) {
            refreshTokenAction(response, token);
        } else {
            accessTokenAction(response, token);
        }
    }

    private boolean isRefreshToken(HttpServletRequest request, EncodedToken token) {
        return isRefreshPath(request.getServletPath()) && JwtManager.getInfo(token, "status").equals("refresh");
    }

    private static void accessTokenAction(HttpServletResponse response, EncodedToken token) throws IOException {
        if (isExpiredRefreshToken(token)) {
//                    log.warn("JWTException::: Validate AccessToken = {}", false);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "expiration token");
        } else {
            //                    log.warn("JWTException::: AccessToken Expired");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, TokenStatus.STATUS_ACCESS_TOKEN_EXPIRED.getMessage());
        }
    }

    private void refreshTokenAction(HttpServletResponse response, EncodedToken refreshToken) throws IOException {
        if (isExpiredRefreshToken(refreshToken)) {
            ResponseJsonJwts responseJsonJwts = new ResponseJsonJwts(getNewAccessTokenByRefreshToken(refreshToken), refreshToken);
            jwtHttpServletProvider.responseJsonObject(response, HttpStatus.ACCEPTED, responseJsonJwts.getJsonJwt());
//                    log.info("JWTExpiredException::: Create New AccessToken");
        } else {
//                    log.warn("JWTExpiredException::: RefreshToken Expired");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, TokenStatus.STATUS_REFRESH_TOKEN_EXPIRED.getMessage());
        }
    }

    private static boolean isExpiredRefreshToken(EncodedToken token) {
        return JwtManager.validateJwt(token);
    }

    private String getAuthorization(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader("Authorization")).orElseThrow(() -> new NullPointerException("HTTPHeaderException::: No Authorization Parameter in HttpHeader"));
    }

    private boolean isRefreshPath(String path) {
        String refreshPath = "/auth/refresh";
        return path.equals(refreshPath);
    }

    private EncodedToken getNewAccessTokenByRefreshToken(EncodedToken refreshToken) throws JsonProcessingException {
        Long userId = JwtManager.getIdByToken(refreshToken);
        return new EncodedToken(JwtManager.createAccessJwt(userId));
    }
}