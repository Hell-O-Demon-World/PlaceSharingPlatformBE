package com.golfzonaca.officesharingplatform.web.payment.validation;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Reservation;
import com.golfzonaca.officesharingplatform.domain.type.FixStatus;
import com.golfzonaca.officesharingplatform.domain.type.PayType;
import com.golfzonaca.officesharingplatform.domain.type.PayWay;
import com.golfzonaca.officesharingplatform.domain.type.ReservationStatus;
import com.golfzonaca.officesharingplatform.exception.InvalidResCancelRequest;
import com.golfzonaca.officesharingplatform.exception.PayFailureException;
import com.golfzonaca.officesharingplatform.repository.payment.PaymentRepository;
import com.golfzonaca.officesharingplatform.repository.reservation.ReservationRepository;
import com.golfzonaca.officesharingplatform.web.payment.form.NicePayRequestForm;
import com.golfzonaca.officesharingplatform.web.validation.RequestValidation;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@Transactional
@RequiredArgsConstructor
public class PaymentValidation {
    private final ReservationRepository reservationRepository;
    private final PaymentRepository paymentRepository;
    private final RequestValidation requestValidation;


    public void validationPayment(Long userId, NicePayRequestForm nicePayRequestForm) {
        requestValidation.validUser(userId);
        requestValidation.validReservation(nicePayRequestForm.getReservationId());
        validRoomTypeOffice(userId, nicePayRequestForm);
    }

    public void validationPaymentCancel(Long userId, Long reservationId) {
        requestValidation.validUser(userId);
        requestValidation.validReservation(reservationId);
        cancelRequest(reservationId);
    }

    public void cancelRequest(long reservationId) {
        Reservation reservation = reservationRepository.findById(reservationId);
        if (reservation.getStatus() != ReservationStatus.COMPLETED || reservation.getFixStatus() != FixStatus.UNFIXED) {
            throw new InvalidResCancelRequest("취소할 수 없는 예약입니다.");
        }
    }

    public void deleteKakaoHistoryOnProgressing(long reservationId) {
        Reservation reservation = reservationRepository.findById(reservationId);
        List<Payment> paymentList = paymentRepository.findByReservationAndProgressingStatus(reservation);
        for (Payment payment : paymentList) {
            paymentRepository.delete(payment);
        }
    }


    private void validRoomTypeOffice(Long userId, NicePayRequestForm nicePayRequestForm) {
        long reservationId = nicePayRequestForm.getReservationId();
        Reservation findReservation = reservationRepository.findByIdAndUserID(reservationId, userId);
        if (findReservation.getRoom().getRoomKind().getRoomType().toString().contains("OFFICE")) {
            if (!nicePayRequestForm.getPayWay().equals(PayWay.POSTPAYMENT.name()) || !nicePayRequestForm.getPayType().equals(PayType.FULL_PAYMENT.name())) {
                throw new PayFailureException("오피스는 후결제, 현장 결제 방식만 가능합니다.");
            }
        }
    }

}
