package com.golfzonaca.officesharingplatform.auth.filter.servlet;

import com.google.gson.JsonObject;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface TokenHttpServletProvider {
    void responseJsonObject(HttpServletResponse response, HttpStatus status, JsonObject jsonObject) throws IOException;

}
