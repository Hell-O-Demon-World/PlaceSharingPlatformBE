package com.golfzonaca.officesharingplatform.repository.rating;

import com.golfzonaca.officesharingplatform.domain.Rating;
import com.golfzonaca.officesharingplatform.domain.User;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.List;

import static com.golfzonaca.officesharingplatform.domain.QRating.rating;

@Repository
@Transactional
public class QueryRatingRepository {
    private final JPAQueryFactory query;

    public QueryRatingRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public Long countByUser(User user) {
        return query
                .select(rating.count())
                .from(rating)
                .where(userEqual(user))
                .orderBy(rating.ratingTime.desc())
                .fetchOne();
    }

    public List<Rating> findAllByUserWithPagination(User user, Integer page) {
        return query
                .selectFrom(rating)
                .innerJoin(rating.reservation.user)
                .where(userEqual(user))
                .orderBy(rating.ratingTime.desc())
                .offset(8L * (page - 1))
                .limit(8)
                .fetch();
    }

    private BooleanExpression userEqual(User user) {
        return rating.reservation.user.eq(user);
    }

}
