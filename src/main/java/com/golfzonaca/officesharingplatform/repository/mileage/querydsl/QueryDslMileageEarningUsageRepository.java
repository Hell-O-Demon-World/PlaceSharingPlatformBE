package com.golfzonaca.officesharingplatform.repository.mileage.querydsl;

import com.golfzonaca.officesharingplatform.domain.*;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import java.util.List;

import static com.golfzonaca.officesharingplatform.domain.QMileageEarningUsage.mileageEarningUsage;
import static com.golfzonaca.officesharingplatform.domain.QMileagePaymentUpdate.mileagePaymentUpdate;
import static com.golfzonaca.officesharingplatform.domain.QMileageTransactionUsage.mileageTransactionUsage;

@Repository
public class QueryDslMileageEarningUsageRepository {
    private final JPAQueryFactory query;

    public QueryDslMileageEarningUsageRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }


    public List<MileageEarningUsage> findAllByMileage(Mileage mileage) {
        return query.selectFrom(mileageEarningUsage)
                .innerJoin(mileageEarningUsage.mileageUpdate)
                .innerJoin(mileageEarningUsage.mileageUpdate.mileage)
                .where(mileageEarningUsage.mileageUpdate.mileage.eq(mileage))
                .fetch();
    }
}
