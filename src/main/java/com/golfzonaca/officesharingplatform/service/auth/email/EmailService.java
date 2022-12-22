package com.golfzonaca.officesharingplatform.service.auth.email;

import com.golfzonaca.officesharingplatform.web.auth.form.EmailForm;

import javax.mail.internet.AddressException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public interface EmailService {
    void sendMail(EmailForm emailForm) throws IOException, AddressException, NoSuchAlgorithmException;

    boolean MatchersByEmailAndCode(String email, String code);
}
