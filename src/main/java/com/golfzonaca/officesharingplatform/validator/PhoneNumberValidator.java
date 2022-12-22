package com.golfzonaca.officesharingplatform.validator;

import com.golfzonaca.officesharingplatform.annotation.PhoneNum;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class PhoneNumberValidator implements ConstraintValidator<PhoneNum, String> {
    @Override
    public void initialize(PhoneNum constraintAnnotation) {
    }

    @Override
    public boolean isValid(String tel, ConstraintValidatorContext context) {
        return tel != null && tel.matches("[0-9]+");
    }
}
