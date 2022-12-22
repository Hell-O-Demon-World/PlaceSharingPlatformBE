package com.golfzonaca.officesharingplatform.repository.comment;

import com.golfzonaca.officesharingplatform.domain.Comment;
import com.golfzonaca.officesharingplatform.domain.Rating;
import com.golfzonaca.officesharingplatform.domain.User;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.List;

import static com.golfzonaca.officesharingplatform.domain.QComment.comment;

@Repository
@Transactional
public class QueryCommentRepository {
    private final JPAQueryFactory query;

    public QueryCommentRepository(EntityManager em) {
        this.query = new JPAQueryFactory(em);
    }

    public List<Comment> findAllByRatingWithPagination(Rating rating, Integer page) {
        return query
                .selectFrom(comment)
                .where(comment.rating.eq(rating))
                .orderBy(comment.dateTime.desc())
                .offset(8L * (page - 1))
                .limit(8)
                .fetch();
    }

    public Long countByUser(User user) {
        return query
                .select(comment.count())
                .from(comment)
                .where(comment.writer.eq(user))
                .orderBy(comment.dateTime.desc())
                .fetchOne();
    }

    public List<Comment> findAllByUser(User user, Integer page) {
        return query
                .selectFrom(comment)
                .where(comment.writer.eq(user))
                .orderBy(comment.dateTime.desc())
                .offset(8L * (page - 1))
                .limit(8)
                .fetch();
    }

    public List<Comment> findAllByRating(Rating rating) {
        return query
                .selectFrom(comment)
                .where(comment.rating.eq(rating))
                .orderBy(comment.dateTime.desc())
                .fetch();
    }
}