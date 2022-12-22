package com.golfzonaca.officesharingplatform.web.auth;

import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.exception.FailedMatchingCodeException;
import com.golfzonaca.officesharingplatform.service.auth.AuthService;
import com.golfzonaca.officesharingplatform.service.auth.email.CustomEmailService;
import com.golfzonaca.officesharingplatform.service.auth.email.VerifyingCodeMaker;
import com.golfzonaca.officesharingplatform.service.auth.validation.AuthRequestValidation;
import com.golfzonaca.officesharingplatform.web.auth.form.AddressForm;
import com.golfzonaca.officesharingplatform.web.auth.form.CodeForm;
import com.golfzonaca.officesharingplatform.web.auth.form.EmailForm;
import com.golfzonaca.officesharingplatform.web.auth.form.SignUpSaveForm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;


@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final AuthService customAuthService;
    private final AuthRequestValidation authRequestValidation;
    private final CustomEmailService customEmailService;

    @ResponseBody
    @PostMapping("/signup")
    public void signup(@Validated @RequestBody SignUpSaveForm signUpSaveForm, BindingResult bindingResult) {
        String password = signUpSaveForm.getPassword();
        String checkedPassword = signUpSaveForm.getCheckedPassword();
        User user = signUpSaveForm.toEntity();
        authRequestValidation.validation(user, bindingResult, password, checkedPassword);
        customAuthService.join(user);
    }

    @GetMapping("/refresh")
    public void refreshToken() {
    }

    @PostMapping("/sendemail")
    public void verifyingMail(@Validated @RequestBody AddressForm address, BindingResult bindingResult) throws NoSuchAlgorithmException{
        authRequestValidation.validation(address.getAddress(), bindingResult);
        String email = address.getAddress();
        String code = VerifyingCodeMaker.makeCode();
        EmailForm emailForm = new EmailForm();
        emailForm.toEntity(email, code);

        customEmailService.sendMail(emailForm);
    }

    @PostMapping("/verifying")
    public void verifyingCode(@Validated @RequestBody CodeForm codeForm, BindingResult bindingResult) {
        authRequestValidation.validation(codeForm.getEmail(), bindingResult);

        String email = codeForm.getEmail();
        String code = codeForm.getCode();
        if (!customEmailService.MatchersByEmailAndCode(email, code)) {
            throw new FailedMatchingCodeException("입력하신 코드가 일치하지 않습니다.");
        }
    }
}
