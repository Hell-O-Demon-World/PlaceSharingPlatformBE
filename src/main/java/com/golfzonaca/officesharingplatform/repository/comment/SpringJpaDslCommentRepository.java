package com.golfzonaca.officesharingplatform.repository.comment;

import com.golfzonaca.officesharingplatform.domain.Comment;
import com.golfzonaca.officesharingplatform.domain.Rating;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.web.comment.dto.CommentData;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.NoSuchElementException;

@Repository
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslCommentRepository implements CommentRepository {

    private final SpringJpaCommentRepository jpaRepository;
    private final QueryCommentRepository queryRepository;


    @Override
    public void save(Comment comment) {
        jpaRepository.save(comment);
    }

    @Override
    public Comment findById(long commentId) {
        return jpaRepository.findById(commentId).orElseThrow(() -> new NoSuchElementException("존재하지 않는 댓글입니다."));
    }

    @Override
    public List<Comment> findAllByRating(Rating rating) {
        return queryRepository.findAllByRating(rating);
    }

    @Override
    public void update(Comment comment, CommentData data) {
        comment.updateComment(data.getContext());
    }

    @Override
    public void delete(Comment comment) {
        jpaRepository.delete(comment);
    }

    @Override
    public Long countByUser(User user) {
        return queryRepository.countByUser(user);
    }

    @Override
    public List<Comment> findAllByUserWithPagination(User user, Integer page) {
        return queryRepository.findAllByUser(user, page);
    }

    @Override
    public List<Comment> findAllByRatingWithPagination(Rating rating, Integer page) {
        return queryRepository.findAllByRatingWithPagination(rating, page);
    }

}
