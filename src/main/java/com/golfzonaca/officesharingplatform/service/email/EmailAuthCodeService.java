package com.golfzonaca.officesharingplatform.service.email;

public interface EmailAuthCodeService {
    boolean MatchersByEmailAndCode(String email, String code);
}
