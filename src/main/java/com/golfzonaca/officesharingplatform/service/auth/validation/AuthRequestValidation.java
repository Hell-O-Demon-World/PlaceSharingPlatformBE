package com.golfzonaca.officesharingplatform.service.auth.validation;

import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.exception.BindingResultErrorException;
import com.golfzonaca.officesharingplatform.exception.InvalidEmailException;
import com.golfzonaca.officesharingplatform.exception.InvalidPhoneNumException;
import com.golfzonaca.officesharingplatform.exception.MisMatchingPasswordException;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import com.golfzonaca.officesharingplatform.web.auth.form.CodeForm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;

import java.util.Objects;

@Component
@RequiredArgsConstructor
public class AuthRequestValidation {
    private static final String MISMATCH_PASSWORDS_MESSAGE = "첫번째 비밀번호 값과 두번째 비밀번호 값이 다릅니다.";
    private final UserRepository userRepository;

    public void validation(User userDto, BindingResult bindingResult, String pw1, String pw2) {
        validPwAndPw2(pw1, pw2);
        bindingResultCheck(bindingResult);
        isAvailableEmail(userDto.getEmail());
        isAvailablePhoneNumber(userDto.getPhoneNumber());
    }

    public void validation(String email, BindingResult bindingResult) {
        bindingResultCheck(bindingResult);
        isAvailableEmail(email);
    }

    private void validPwAndPw2(String pw, String pw2) {
        if (!pw.equals(pw2)) {
            throw new MisMatchingPasswordException(MISMATCH_PASSWORDS_MESSAGE);
        }
    }

    private void bindingResultCheck(BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            for (ObjectError objectError : bindingResult.getAllErrors()) {
                String msg = objectError.getCode() + "ValidationError::: " + Objects.requireNonNull(objectError.getDefaultMessage());
                throw new BindingResultErrorException(msg);
            }
        }
    }

    private void isAvailableEmail(String email) {
        if (!userRepository.isUniqueEmail(email)) {
            throw new InvalidEmailException("InvalidEmailException::: 사용할 수 없는 메일입니다.");
        }
    }

    private void isAvailablePhoneNumber(String phoneNumber) {
        if (!userRepository.isUniqueTel(phoneNumber)) {
            throw new InvalidPhoneNumException("InvalidPhoneNumException::: 사용할 수 없는 전화번호입니다.");
        }
    }
}