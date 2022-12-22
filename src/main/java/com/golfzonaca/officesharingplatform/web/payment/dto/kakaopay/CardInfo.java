package com.golfzonaca.officesharingplatform.web.payment.dto.kakaopay;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CardInfo {

    private String purchaseCorp;
    private String purchaseCorpCode;
    private String issuerCorp;
    private String issuerCorpCode;
    private String kakaopayPurchaseCorp;
    private String kakaopayPurchaseCorpCode;
    private String kakaopayIssuerCorp;
    private String kakaopayIssuerCorpCode;
    private String bin;
    private String cardType;
    private String installMonth;
    private String approvedId;
    private String cardMid;
    private String interestFreeInstall;
    private String cardItemCode;
}
