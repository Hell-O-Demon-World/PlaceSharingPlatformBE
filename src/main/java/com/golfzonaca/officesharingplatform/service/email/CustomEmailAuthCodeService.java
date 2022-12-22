package com.golfzonaca.officesharingplatform.service.email;

import com.golfzonaca.officesharingplatform.repository.email.EmailAuthCodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Service
@RequiredArgsConstructor
public class CustomEmailAuthCodeService implements EmailAuthCodeService {
    private final EmailAuthCodeRepository emailAuthCodeRepository;
    @Override
    public boolean MatchersByEmailAndCode(String email, String code) {
        return emailAuthCodeRepository.findFirstByEmailAndCode(email, code);
    }
}
