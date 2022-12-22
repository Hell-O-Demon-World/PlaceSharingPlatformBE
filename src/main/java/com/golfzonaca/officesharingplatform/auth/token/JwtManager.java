package com.golfzonaca.officesharingplatform.auth.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.TimeZone;

@RequiredArgsConstructor
public class JwtManager {
    private static final MacSigner macSigner = new MacSigner("Hell-o-World");
    private static final Gson gson = new Gson();

    public static Jwt createAccessJwt(Long userId) {
        Jwt newToken = JwtManager.createJwt(userId.toString(), "access");
        return newToken;
    }

    public static Jwt createRefreshJwt(Long userId) {
        Jwt newToken = JwtManager.createJwt(userId.toString(), "refresh");
        return newToken;
    }

    public static Jwt createJwt(String id, String status) {
        return JwtHelper.encode(createPayload(id, status), macSigner);
    }

    private static String createPayload(String id, String status) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("id", id);
        jsonObject.addProperty("status", status);
        jsonObject.addProperty("iat", getIssueAt());

        return gson.toJson(jsonObject);
    }

    private static long getIssueAt() {
        return System.currentTimeMillis();
    }

    private static LocalDateTime getAccessTime(LocalDateTime iatDateTime) {
        return iatDateTime.plusMinutes(30);
    }

    private static LocalDateTime getRefreshTime(LocalDateTime iatDateTime) {
        return iatDateTime.plusWeeks(1);
    }

    private static boolean isTimeOverIat(long iat, String status) {
        LocalDateTime iatDateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(iat), TimeZone.getDefault().toZoneId());
        if (status.equals("access")) {
            return getAccessTime(iatDateTime).isAfter(LocalDateTime.now());
        } else {
            return getRefreshTime(iatDateTime).isAfter(LocalDateTime.now());
        }
    }

    public static boolean isAccessToken(String jwt) {
        JsonObject jsonObject = getJsonObject(jwt);
        JsonElement statusJson = jsonObject.get("status");
        String status = statusJson.getAsString();
        return status.equals("access");
    }

    public static boolean validateJwt(String jwt) {

        JsonObject jsonObject = getJsonObject(jwt);
        JsonElement iatJson = jsonObject.get("iat");
        long iat = iatJson.getAsLong();
        JsonElement statusJson = jsonObject.get("status");
        String status = statusJson.getAsString();
        return isTimeOverIat(iat, status);
    }

    public static String getInfo(String jwt, String attr) {

        JsonObject jsonObject = getJsonObject(jwt);
        JsonElement jsonElement = jsonObject.get(attr);

        return jsonElement.getAsString();
    }

    private static JsonObject getJsonObject(String jwt) {

        Jwt decodedJwt = JwtHelper.decodeAndVerify(jwt, macSigner);

        String claims = decodedJwt.getClaims();

        return gson.fromJson(claims, JsonObject.class);
    }

    public static Long getIdByToken(String token) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        String claims = JwtHelper.decode(token).getClaims();
        return Long.parseLong(objectMapper.readValue(claims, Map.class).get("id").toString());
    }
}