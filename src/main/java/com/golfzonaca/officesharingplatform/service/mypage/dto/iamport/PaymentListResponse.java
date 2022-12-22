package com.golfzonaca.officesharingplatform.service.mypage.dto.iamport;

import lombok.Getter;
import lombok.Setter;

import java.util.Optional;

@Getter
@Setter
public class PaymentListResponse {
    private Integer code;
    private String message;
    private Optional<PagedPaymentAnnotation> response;
}
