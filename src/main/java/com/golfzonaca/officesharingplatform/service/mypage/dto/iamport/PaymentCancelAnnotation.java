package com.golfzonaca.officesharingplatform.service.mypage.dto.iamport;

import lombok.Getter;
import lombok.Setter;

import java.util.Optional;

@Getter
@Setter
public class PaymentCancelAnnotation {
    private String pg_tid;
    private Number amount;
    private Integer cancelled_at;
    private String reason;
    private Optional<String> receipt_url;
}
