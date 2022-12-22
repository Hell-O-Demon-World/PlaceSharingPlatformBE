package com.golfzonaca.officesharingplatform.annotation;

import com.golfzonaca.officesharingplatform.validator.RequestFilterDataNotBlankValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = RequestFilterDataNotBlankValidator.class)
public @interface RequestFilterDataNotBlank {
    String message() default "입력한 값이 없습니다.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    String day();

    String startTime();

    String endTime();

    String city();

    String subCity();

    String type();
}
