package com.golfzonaca.officesharingplatform.repository.email;

import com.golfzonaca.officesharingplatform.domain.EmailAuthenticationCode;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaEmailAuthCodeRepository extends JpaRepository<EmailAuthenticationCode, Long> {
    EmailAuthenticationCode save(EmailAuthCodeRepository emailAuthCodeRepository);
}
