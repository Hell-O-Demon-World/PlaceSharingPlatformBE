package com.golfzonaca.officesharingplatform.service.payment;


import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Reservation;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.domain.type.PayType;
import com.golfzonaca.officesharingplatform.domain.type.PayWay;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;

import java.time.LocalDateTime;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

public class PaymentValidation {

    public List<Payment> cancelAvailableTimeValidation(Reservation reservation) {

        List<Payment> availableCancelTarget = new LinkedList<>();

        LocalDateTime reservationTime = reservation.getResCompleted().plusHours(1);
        LocalDateTime now = LocalDateTime.now();

        if (reservationTime.isBefore(now)) {
            for (Payment payment : reservation.getPaymentList()) {

                if (payment.getType().equals(PayType.FULL_PAYMENT) || payment.getType().equals(PayType.BALANCE)) {
                    availableCancelTarget.add(payment);
                }
            }
            return availableCancelTarget;
        } else {
            return reservation.getPaymentList();
        }
    }

    public void validExistedType(String payType) {
        for (PayType supportedType : PayType.values()) {
            if (supportedType.toString().equals(payType)) {
                return;
            }
        }
        throw new NoSuchElementException("지원하지 않는 결제 유형입니다.");
    }

    public void validExistedPayWay(String payWay) {
        for (PayWay supportedPayWay : PayWay.values()) {
            if (supportedPayWay.toString().equals(payWay)) {
                return;
            }
        }
        throw new NoSuchElementException("지원하지 않는 결제 방식입니다.");
    }

    public void validPairByRoomType(String payType, String payWay, RoomType roomType) {

        if (roomType.toString().contains("OFFICE")) {
            if (payWay.equals(PayWay.POSTPAYMENT.toString()) && payType.equals(PayType.FULL_PAYMENT.toString())) {

            } else {
                throw new NoSuchElementException("오피스 타입에 지원되지 않는 결제 방식과 타입입니다.");
            }
        } else {

            if (payWay.equals(PayWay.PREPAYMENT.toString()) && payType.equals(PayType.DEPOSIT.toString())) {

            } else if (payWay.equals(PayWay.PREPAYMENT.toString()) && payType.equals(PayType.FULL_PAYMENT.toString())) {

            } else if (payWay.equals(PayWay.POSTPAYMENT.toString()) && payType.equals(PayType.BALANCE.toString())) {

            } else {
                throw new NoSuchElementException("지원하지 않는 선결제 방식과 타입입니다.");
            }
        }
    }

    public void validUserForReservation(User user, Reservation reservation) {

        if (reservation.getUser() != user) {
            throw new NoSuchElementException("유저 정보가 일치하지 않습니다.");
        }
    }
}