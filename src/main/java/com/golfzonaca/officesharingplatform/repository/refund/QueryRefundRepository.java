package com.golfzonaca.officesharingplatform.repository.refund;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Refund;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QRefund.refund;

@Transactional
@Repository
public class QueryRefundRepository {
    private final JPAQueryFactory query;

    public QueryRefundRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }


    public Optional<Refund> findByPayment(Payment payment) {
        return Optional.ofNullable(query
                .selectFrom(refund)
                .where(refund.payment.eq(payment))
                .fetchFirst());
    }
}
