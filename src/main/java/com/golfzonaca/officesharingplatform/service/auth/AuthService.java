package com.golfzonaca.officesharingplatform.service.auth;


import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.web.auth.form.EmailForm;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public interface AuthService {

    String findUserEmail(String name, String tel);
    void join(User user);
    boolean isAvailableTelNum(String phoneNumber);
    void sendMail(EmailForm emailForm) throws NoSuchAlgorithmException, UnsupportedEncodingException;

    void createNewPassword(String email, String newPassword);
}
