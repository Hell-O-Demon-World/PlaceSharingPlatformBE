package com.golfzonaca.officesharingplatform.repository.email;

import com.golfzonaca.officesharingplatform.domain.EmailAuthenticationCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.function.Supplier;

@Transactional
@Repository
@RequiredArgsConstructor
public class CustomEmailAuthCodeRepository implements EmailAuthCodeRepository {
    private final QueryEmailAuthCodeRepository queryEmailAuthCodeRepository;
    private final SpringJpaEmailAuthCodeRepository jpaEmailAuthCOdeRepository;

    @Override
    public boolean findFirstByEmailAndCode(String email, String code) {
        return queryEmailAuthCodeRepository.findFirstByMailAndCode(email, code).isPresent();
    }

    @Override
    public EmailAuthenticationCode save(EmailAuthenticationCode emailAuthenticationCode) {
        return jpaEmailAuthCOdeRepository.save(emailAuthenticationCode);
    }

    @Override
    public EmailAuthenticationCode findFirstByEmail(String email) {
        return queryEmailAuthCodeRepository.findFirstByEmail(email).orElseGet(EmailAuthenticationCode::new);
    }
}
