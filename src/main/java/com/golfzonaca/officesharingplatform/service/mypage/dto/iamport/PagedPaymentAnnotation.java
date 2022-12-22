package com.golfzonaca.officesharingplatform.service.mypage.dto.iamport;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
public class PagedPaymentAnnotation {
    private Integer total;
    private Integer previous;
    private Integer next;
    private Optional<List<PaymentAnnotation>> list;
}
