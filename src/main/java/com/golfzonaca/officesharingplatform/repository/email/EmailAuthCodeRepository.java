package com.golfzonaca.officesharingplatform.repository.email;

import com.golfzonaca.officesharingplatform.domain.EmailAuthenticationCode;

public interface EmailAuthCodeRepository {
    boolean findFirstByEmailAndCode(String email, String code);

    EmailAuthenticationCode save(EmailAuthenticationCode emailAuthenticationCode);

    EmailAuthenticationCode findFirstByEmail(String email);
}
