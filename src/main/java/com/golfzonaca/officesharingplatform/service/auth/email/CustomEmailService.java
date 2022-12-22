package com.golfzonaca.officesharingplatform.service.auth.email;

import com.golfzonaca.officesharingplatform.domain.EmailAuthenticationCode;
import com.golfzonaca.officesharingplatform.repository.email.EmailAuthCodeRepository;
import com.golfzonaca.officesharingplatform.web.auth.form.EmailForm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Transactional
@Service
@RequiredArgsConstructor
public class CustomEmailService implements EmailService {
    private final JavaMailSender javaMailSender;
    private final EmailAuthCodeRepository emailAuthCodeRepository;

    @Override
    public void sendMail(EmailForm emailForm) {
        EmailAuthenticationCode emailAuthenticationCode = findByEmail(emailForm.getAddress());

        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setFrom("ryeongee21@naver.com");
        simpleMailMessage.setTo(emailForm.getAddress());
        simpleMailMessage.setSubject(emailForm.getTitle());
        simpleMailMessage.setText(emailForm.getMessage());
        javaMailSender.send(simpleMailMessage);
        emailAuthenticationCode.toEntity(emailForm.getAddress(), emailForm.getCode(), true);
        emailAuthCodeRepository.save(emailAuthenticationCode);
    }

    @Override
    public boolean MatchersByEmailAndCode(String email, String code) {
        return emailAuthCodeRepository.findFirstByEmailAndCode(email, code);
    }

    public EmailAuthenticationCode findByEmail(String email) {
        return emailAuthCodeRepository.findFirstByEmail(email);
    }
}
