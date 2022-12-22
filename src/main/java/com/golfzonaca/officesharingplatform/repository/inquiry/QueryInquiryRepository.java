package com.golfzonaca.officesharingplatform.repository.inquiry;

import com.golfzonaca.officesharingplatform.domain.Inquiry;
import com.golfzonaca.officesharingplatform.domain.User;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.List;

import static com.golfzonaca.officesharingplatform.domain.QInquiry.inquiry;

@Repository
@Transactional
public class QueryInquiryRepository {

    private final JPAQueryFactory query;

    public QueryInquiryRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public List<Inquiry> findByUserWithPagination(User user, long page) {
        return query
                .selectFrom(inquiry)
                .where(inquiry.user.eq(user))
                .orderBy(inquiry.dateTime.desc())
                .offset(8L * (page - 1))
                .limit(8)
                .fetch();
    }
}