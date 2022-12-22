package com.golfzonaca.officesharingplatform.repository.refund;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Refund;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@RequiredArgsConstructor
@Repository
@Transactional
public class CustomRefundRepository implements RefundRepository {

    private final SpringJpaRefundRepository jpaRepository;
    private final QueryRefundRepository queryRepository;

    @Override
    public void save(Refund refund) {
        jpaRepository.save(refund);
    }

    @Override
    public Optional<Refund> findByPayment(Payment payment) {
        return queryRepository.findByPayment(payment);
    }
}
