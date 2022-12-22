package com.golfzonaca.officesharingplatform.repository.payment;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Reservation;

import java.util.List;

public interface PaymentRepository {

    Payment save(Payment payment);

    List<Payment> findByReservationId(long reservationId);

    Payment findById(long paymentId);

    List<Payment> findProgressingPaymentByReservation(Reservation reservation);

    void delete(Payment payment);

    List<Payment> findByReservationAndProgressingStatus(Reservation reservation);
}
