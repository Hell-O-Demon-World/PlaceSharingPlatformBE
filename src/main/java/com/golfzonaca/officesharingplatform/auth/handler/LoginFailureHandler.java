package com.golfzonaca.officesharingplatform.auth.handler;

import com.golfzonaca.officesharingplatform.auth.filter.servlet.JwtHttpServletProvider;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Calendar;

@Component
@RequiredArgsConstructor
public class LoginFailureHandler implements AuthenticationFailureHandler {
    private final JwtHttpServletProvider jwtHttpServletProvider;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        JsonObject json = new JsonObject();
        json.addProperty("timestamp", String.valueOf(Calendar.getInstance().getTime()));
        json.addProperty("status", HttpServletResponse.SC_UNAUTHORIZED);
        json.addProperty("message", "아이디 비밀번호를 확인해주세요");
        jwtHttpServletProvider.responseJsonObject(response, HttpStatus.UNAUTHORIZED, json);
    }
}

