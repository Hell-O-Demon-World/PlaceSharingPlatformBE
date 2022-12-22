package com.golfzonaca.officesharingplatform.repository.refreshtoken;

import com.golfzonaca.officesharingplatform.domain.RefreshToken;
import com.querydsl.core.QueryFactory;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;

import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QUser.user;

import static com.golfzonaca.officesharingplatform.domain.QRefreshToken.refreshToken;

@Repository
@Transactional
public class QueryRefreshTokenRepository {
    private final JPAQueryFactory query;

    public QueryRefreshTokenRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public Optional<RefreshToken> findFirstById(Long id) {
        return Optional.ofNullable(query.selectFrom(refreshToken)
                .where(refreshToken.id.eq(id))
                .fetchFirst());
    }

    public Optional<RefreshToken> findFirstByUserId(Long userId) {
        return Optional.ofNullable(query.selectFrom(refreshToken)
                .innerJoin(refreshToken.user)
                .where(refreshToken.user.id.eq(userId))
                .fetchFirst());
    }

    public Optional<RefreshToken> isContainByUserId(Long userId) {
        return Optional.ofNullable(query.selectFrom(refreshToken)
                .where(refreshToken.id.eq(userId))
                .fetchFirst());
    }

    public void deleteByUserId(Long userId) {
        RefreshToken findRefreshToken = query.selectFrom(refreshToken)
                .innerJoin(user)
                .where(refreshToken.user.id.eq(userId))
                .fetchFirst();

        query.delete(refreshToken)
                .where(refreshToken.id.eq(findRefreshToken.getId()));
    }

    public RefreshToken findByUserId(Long userId) {
        return query.selectFrom(refreshToken)
                .innerJoin(user)
                .where(refreshToken.user.id.eq(userId))
                .fetchFirst();
    }
}
