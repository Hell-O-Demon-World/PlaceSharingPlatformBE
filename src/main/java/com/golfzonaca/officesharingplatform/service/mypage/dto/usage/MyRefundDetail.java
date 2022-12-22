package com.golfzonaca.officesharingplatform.service.mypage.dto.usage;

import lombok.AllArgsConstructor;
import lombok.Builder;

@Builder
@AllArgsConstructor
public class MyRefundDetail {
    private String refundDate;
    private String refundTime;
    private Long refundPrice;
    private Long refundMileage;
    private String refundReceipt;
}
