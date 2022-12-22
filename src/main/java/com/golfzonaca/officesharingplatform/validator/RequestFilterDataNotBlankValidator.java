package com.golfzonaca.officesharingplatform.validator;

import com.golfzonaca.officesharingplatform.annotation.RequestFilterDataNotBlank;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.lang.reflect.Field;

@Component
public class RequestFilterDataNotBlankValidator implements ConstraintValidator<RequestFilterDataNotBlank, Object> {

    private String field1;
    private String field2;
    private String field3;
    private String field4;
    private String field5;
    private String field6;

    @Override
    public void initialize(RequestFilterDataNotBlank annotation) {
        field1 = annotation.day();
        field2 = annotation.startTime();
        field3 = annotation.endTime();
        field4 = annotation.city();
        field5 = annotation.subCity();
        field6 = annotation.type();
    }

    @Override
    public boolean isValid(Object object, ConstraintValidatorContext context) {
        String day = getFieldValue(object, field1);
        String startTime = getFieldValue(object, field2);
        String endTime = getFieldValue(object, field3);
        String city = getFieldValue(object, field4);
        String subCity = getFieldValue(object, field5);
        String type = getFieldValue(object, field6);
        if (!(StringUtils.hasText(day)) && !(StringUtils.hasText(startTime)) && !(StringUtils.hasText(endTime)) && !(StringUtils.hasText(city)) && !(StringUtils.hasText(subCity)) && !(StringUtils.hasText(type))) {
            return false;
        }
        return true;
    }

    private String getFieldValue(Object object, String fieldName) {
        Class<?> clazz = object.getClass();
        try {
            Field dataField = clazz.getDeclaredField(fieldName);
            dataField.setAccessible(true);
            Object target = dataField.get(object);
            if (!(target instanceof String)) {
                throw new ClassCastException("casting exception");
            }
            return (String) target;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
