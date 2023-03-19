package com.golfzonaca.officesharingplatform.auth.filter.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.golfzonaca.officesharingplatform.auth.TokenStatus;
import com.golfzonaca.officesharingplatform.auth.filter.servlet.JwtHttpServletProvider;
import com.golfzonaca.officesharingplatform.auth.token.EncodedToken;
import com.golfzonaca.officesharingplatform.auth.token.JwtManager;
import com.golfzonaca.officesharingplatform.auth.token.ResponseJsonJwts;
import com.google.gson.JsonObject;
import com.sun.xml.bind.v2.runtime.output.Encoded;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final JwtHttpServletProvider jwtHttpServletProvider;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String path = request.getServletPath();

        EncodedToken encodedToken = new EncodedToken(getAuthorization(request));

        tokenAction(request, response, encodedToken);
        Assertions.assertThat(10).isEqualTo(10);
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
