package com.golfzonaca.officesharingplatform.repository.company;

import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;

@Repository
@Transactional
public class QueryCompanyRepository {
    private final JPAQueryFactory query;

    public QueryCompanyRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }
}
