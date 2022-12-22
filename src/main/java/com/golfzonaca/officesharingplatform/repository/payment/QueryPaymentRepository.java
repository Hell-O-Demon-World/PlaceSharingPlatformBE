package com.golfzonaca.officesharingplatform.repository.payment;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Reservation;
import com.golfzonaca.officesharingplatform.domain.type.PaymentStatus;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.List;

import static com.golfzonaca.officesharingplatform.domain.QPayment.payment;

@Repository
@Transactional
public class QueryPaymentRepository {

    private final JPAQueryFactory query;

    public QueryPaymentRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public List<Payment> findByReservationId(long reservationId) {
        return query
                .selectFrom(payment)
                .where(payment.reservation.id.eq(reservationId))
                .fetch();
    }

    public List<Payment> findNotCanceledPaymentByReservation(Reservation reservation) {
        return query
                .selectFrom(payment)
                .where(payment.reservation.eq(reservation), payment.payStatus.ne(PaymentStatus.CANCELED))
                .fetch();
    }

    public List<Payment> findByReservationAndProgressingStatus(Reservation reservation) {
        return query
                .selectFrom(payment)
                .where(payment.reservation.eq(reservation), payment.payStatus.eq(PaymentStatus.PROGRESSING))
                .fetch();
    }
}