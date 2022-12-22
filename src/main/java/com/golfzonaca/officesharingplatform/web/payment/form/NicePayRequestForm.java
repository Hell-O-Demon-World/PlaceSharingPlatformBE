package com.golfzonaca.officesharingplatform.web.payment.form;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Getter;

@Getter
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class NicePayRequestForm {

    private long reservationId;
    private long payMileage;
    private String payWay;
    private String payType;
    private String card_number;
    private String expiry;
    private String birth;
    private String pwd_2digit;
    private String cvc;
    private Integer card_quota;
    private final String pg = "nice";

    public void changePayTypeAndPayWay(String payType, String payWay) {
        this.payType = payType;
        this.payWay = payWay;
    }
}
