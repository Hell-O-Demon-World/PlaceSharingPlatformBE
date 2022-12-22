package com.golfzonaca.officesharingplatform.repository.user;

import com.golfzonaca.officesharingplatform.domain.User;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import javax.persistence.EntityManager;
import java.util.List;
import java.util.Optional;

import static com.golfzonaca.officesharingplatform.domain.QUser.user;


@Repository
@Transactional
public class QueryUserRepository {
    private final JPAQueryFactory query;

    public QueryUserRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public Optional<User> isContainByEmail(String email) {
        return Optional.ofNullable(query
                .select(user)
                .from(user)
                .where(user.email.eq(email))
                .fetchFirst());
    }

    public Optional<User> isContainById(Long userId) {
        return Optional.ofNullable(query
                .select(user)
                .from(user)
                .where(user.id.eq(userId))
                .fetchFirst());
    }

    public List<User> findAll(UserSearchCond cond) {
        String name = cond.getName();
        String mail = cond.getMail();
        String job = cond.getJob();
        String phoneNumber = cond.getPhoneNumber();
        String userPlace = cond.getUserPlace();

        return query
                .select(user)
                .from(user)
                .where(likeName(name), likeMail(mail), likeJob(job), likePhoneNumber(phoneNumber), likeUserPlace(userPlace))
                .fetch();
    }

    private BooleanExpression likeName(String name) {
        if (StringUtils.hasText(name)) {
            return user.username.like(name);
        }
        return null;
    }

    private BooleanExpression likeMail(String mail) {
        if (StringUtils.hasText(mail)) {
            return user.email.like(mail);
        }
        return null;
    }

    private BooleanExpression likeJob(String job) {
        if (StringUtils.hasText(job)) {
            return user.job.like(job);
        }
        return null;
    }

    private BooleanExpression likePhoneNumber(String phoneNumber) {
        if (StringUtils.hasText(phoneNumber)) {
            return user.phoneNumber.like(phoneNumber);
        }
        return null;
    }

    private BooleanExpression likeUserPlace(String userPlace) {
        if (StringUtils.hasText(userPlace)) {
            return user.userPlace.like(userPlace);
        }
        return null;
    }

    public Optional<User> findByTelLike(String phoneNumber) {
        return Optional.ofNullable(query.selectFrom(user)
                .where(user.phoneNumber.like(phoneNumber))
                .fetchFirst());
    }

    public Optional<User> findByNameLike(String name) {
        return Optional.ofNullable(query.selectFrom(user)
                .where(user.username.like(name))
                .fetchFirst());
    }

    public Optional<User> findByNameAndTelLike(String name, String tel) {
        return Optional.ofNullable(query.selectFrom(user)
                .where(user.username.like(name).and(user.phoneNumber.like(tel)))
                .fetchFirst());
    }

    public Optional<User> findByMailAndTel(String email, String tel) {
        return Optional.ofNullable(query.selectFrom(user)
                .where(user.email.like(email).and(user.phoneNumber.like(tel)))
                .fetchFirst());
    }
}
