package com.golfzonaca.officesharingplatform.auth.filter.servlet;

import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
@Component
public class JwtHttpServletProvider implements TokenHttpServletProvider {
    @Override
    public void responseJsonObject(HttpServletResponse response, HttpStatus status, JsonObject jsonObject) throws IOException {
        response.setCharacterEncoding("UTF-8");
        try (PrintWriter out = response.getWriter()) {
            response.setStatus(status.value());
            response.setContentType("application/json; charset=UTF-8");
            out.print(jsonObject);
            out.flush();
        } catch (IOException e) {
            log.error("fail to process file={}", e);
        }
    }
}
