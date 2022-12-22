package com.golfzonaca.officesharingplatform.annotation;

import com.golfzonaca.officesharingplatform.validator.PhoneNumberValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PhoneNumberValidator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface PhoneNum {
    String message() default "유효하지 않은 전화번호 입니다.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
