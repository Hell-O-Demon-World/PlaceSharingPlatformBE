package com.golfzonaca.officesharingplatform.web.payment.dto.kakaopay;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class KakaoPayCancelRequest {

    private String cid;
    private String tid;
    private Integer cancelAmount;
    private Integer cancelTaxFreeAmount;
    private Integer cancelVatAmount;
}
