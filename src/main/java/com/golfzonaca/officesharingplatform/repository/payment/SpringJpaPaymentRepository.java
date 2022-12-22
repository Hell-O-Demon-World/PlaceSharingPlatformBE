package com.golfzonaca.officesharingplatform.repository.payment;

import com.golfzonaca.officesharingplatform.domain.Payment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaPaymentRepository extends JpaRepository<Payment, Long> {
}
