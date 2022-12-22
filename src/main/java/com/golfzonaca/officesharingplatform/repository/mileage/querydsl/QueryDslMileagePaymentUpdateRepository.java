package com.golfzonaca.officesharingplatform.repository.mileage.querydsl;

import com.golfzonaca.officesharingplatform.domain.MileagePaymentUpdate;
import com.golfzonaca.officesharingplatform.domain.MileageTransactionUsage;
import com.golfzonaca.officesharingplatform.domain.MileageUpdate;
import com.golfzonaca.officesharingplatform.domain.Payment;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;

import java.util.List;
import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QMileagePaymentUpdate.mileagePaymentUpdate;
import static com.golfzonaca.officesharingplatform.domain.QMileageTransactionUsage.mileageTransactionUsage;

@Repository
public class QueryDslMileagePaymentUpdateRepository {
    private final JPAQueryFactory query;

    public QueryDslMileagePaymentUpdateRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public Optional<MileagePaymentUpdate> findFirstMileageByPayment(Payment payment) {
        return Optional.ofNullable(query.selectFrom(mileagePaymentUpdate)
                .innerJoin(mileagePaymentUpdate.payment)
                .where(mileagePaymentUpdate.payment.eq(payment))
                .fetchFirst());
    }

    public List<MileageTransactionUsage> findTransactionUsageMileageByPaymentMileage(MileagePaymentUpdate mileagePaymentUpdate) {
        return query.selectFrom(mileageTransactionUsage)
                .innerJoin(mileageTransactionUsage.mileagePaymentUpdate)
                .where(mileageTransactionUsage.mileagePaymentUpdate.id.eq(mileagePaymentUpdate.getId()))
                .fetch();
    }

    public MileagePaymentUpdate findFirstMileageByUpdate(MileageUpdate mileageUpdate) {
        return query.selectFrom(mileagePaymentUpdate)
                .innerJoin(mileagePaymentUpdate.mileageUpdate)
                .where(mileagePaymentUpdate.mileageUpdate.eq(mileageUpdate))
                .fetchFirst();
    }
}
