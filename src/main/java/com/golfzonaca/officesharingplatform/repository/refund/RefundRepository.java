package com.golfzonaca.officesharingplatform.repository.refund;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Refund;

import java.util.Optional;

public interface RefundRepository {

    void save(Refund refund);

    Optional<Refund> findByPayment(Payment payment);
}
