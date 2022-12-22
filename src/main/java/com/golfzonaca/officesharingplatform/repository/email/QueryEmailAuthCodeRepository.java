package com.golfzonaca.officesharingplatform.repository.email;

import com.golfzonaca.officesharingplatform.domain.EmailAuthenticationCode;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QEmailAuthenticationCode.emailAuthenticationCode;


@Repository
@Transactional
public class QueryEmailAuthCodeRepository {
    private final JPAQueryFactory query;

    public QueryEmailAuthCodeRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    Optional<EmailAuthenticationCode> findFirstByMailAndCode(String mail, String code) {
        return Optional.ofNullable(query
                .selectFrom(emailAuthenticationCode)
                .where(emailAuthenticationCode.email.eq(mail), emailAuthenticationCode.verifyingCode.eq(code))
                .fetchFirst());
    }

    public Optional<EmailAuthenticationCode> findFirstByEmail(String mail) {
        return Optional.ofNullable(query
                .selectFrom(emailAuthenticationCode)
                .where(emailAuthenticationCode.email.eq(mail))
                .fetchFirst());
    }
}
