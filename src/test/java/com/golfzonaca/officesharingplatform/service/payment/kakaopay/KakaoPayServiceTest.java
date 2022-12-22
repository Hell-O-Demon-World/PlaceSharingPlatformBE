package com.golfzonaca.officesharingplatform.service.payment.kakaopay;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.type.PayType;
import com.golfzonaca.officesharingplatform.domain.type.PaymentStatus;
import com.golfzonaca.officesharingplatform.repository.payment.PaymentRepository;
import com.golfzonaca.officesharingplatform.repository.reservation.ReservationRepository;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import com.golfzonaca.officesharingplatform.service.mileage.MileageService;
import com.golfzonaca.officesharingplatform.service.refund.RefundService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@RequiredArgsConstructor
class KakaoPayServiceTest {
    private static final String HOST = "https://kapi.kakao.com/";

    private final ReservationRepository reservationRepository;
    private final PaymentRepository paymentRepository;
    private final MileageService mileageService;
    private final UserRepository userRepository;
    private final RefundService refundService;

    @Test
    void kakaoPayReadyRequest() {

    }

    @Test
    void kakaoPayApprovalRequest() {
        //given
        Payment payment = paymentRepository.findById(4L);

        //when
        if (payment.getPayMileage() > 0) {
            mileageService.payingMileage(payment);
        }

        if (PayType.FULL_PAYMENT.equals(payment.getType())) {
            mileageService.savingFullPaymentMileage(payment);
        }
        payment.updatePayStatus(PaymentStatus.COMPLETED);

    }

    @Test
    void kakaoPayCancel() {
    }

    @Test
    void kakaoPayCancelRequest() {
    }

    @Test
    void restoreUserMileage() {
    }

    @Test
    void sendKakaoPayReadyRequest() {
    }

    @Test
    void sendKakaoPayApprovalRequest() {
    }

    @Test
    void sendKakaoPayCancelRequest() {
    }
}