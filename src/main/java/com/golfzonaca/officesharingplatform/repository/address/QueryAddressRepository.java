package com.golfzonaca.officesharingplatform.repository.address;

import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;

@Repository
@Transactional
public class QueryAddressRepository {

    private final JPAQueryFactory query;

    public QueryAddressRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }
}
