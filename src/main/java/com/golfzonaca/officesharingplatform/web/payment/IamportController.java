package com.golfzonaca.officesharingplatform.web.payment;

import com.golfzonaca.officesharingplatform.annotation.TokenUserId;
import com.golfzonaca.officesharingplatform.service.mypage.MyPageService;
import com.golfzonaca.officesharingplatform.service.payment.iamport.IamportService;
import com.golfzonaca.officesharingplatform.web.payment.dto.CancelInfo;
import com.golfzonaca.officesharingplatform.web.payment.form.NicePayRequestForm;
import com.golfzonaca.officesharingplatform.web.payment.validation.PaymentValidation;
import com.google.gson.JsonObject;
import com.siot.IamportRestClient.exception.IamportResponseException;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/payment")
@RequiredArgsConstructor
public class IamportController {
    private final IamportService iamportService;
    private final PaymentValidation paymentValidation;
    private final MyPageService myPageService;

    @PostMapping("/nicepay")
    public String nicePay(@TokenUserId Long userId, @RequestBody NicePayRequestForm nicePayRequestForm) throws IamportResponseException, IOException {
        paymentValidation.validationPayment(userId, nicePayRequestForm);
        return iamportService.requestNicePay(userId, nicePayRequestForm);
    }

    @PostMapping("/nicepaycancel")
    public Map<String, JsonObject> nicepayCancel(@TokenUserId Long userId, @RequestBody CancelInfo cancelInfo) throws IamportResponseException, IOException {
        long reservationId = cancelInfo.getReservationId();
        paymentValidation.validationPaymentCancel(userId, reservationId);
        iamportService.cancelByReservationAndUserId(reservationId, userId);
        iamportService.nicePayCancel(reservationId);
        return myPageService.getResDetailViewData(userId, reservationId);
    }

}
