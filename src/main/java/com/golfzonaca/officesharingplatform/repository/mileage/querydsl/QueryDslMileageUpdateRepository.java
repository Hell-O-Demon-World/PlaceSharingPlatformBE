package com.golfzonaca.officesharingplatform.repository.mileage.querydsl;

import com.golfzonaca.officesharingplatform.domain.*;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import static com.golfzonaca.officesharingplatform.domain.QInquiry.inquiry;
import static com.golfzonaca.officesharingplatform.domain.QMileageUpdate.mileageUpdate;

@Repository
public class QueryDslMileageUpdateRepository {
    private final JPAQueryFactory query;

    public QueryDslMileageUpdateRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public List<MileageUpdate> findByMileageWithPagination(Mileage mileage, long page, long items) {
        return query
                .selectFrom(mileageUpdate)
                .where(mileageUpdate.mileage.eq(mileage))
                .orderBy(mileageUpdate.updateDate.desc())
                .offset(items * (page - 1))
                .limit(items)
                .fetch();
    }
}
