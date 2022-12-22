package com.golfzonaca.officesharingplatform.service.mypage.dto.usage;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class MyPaymentDetail {
    private String payDate;
    private String payTime;
    private long payPrice;
    private long payMileage;
    private String payType;
    private String receipt;
}
