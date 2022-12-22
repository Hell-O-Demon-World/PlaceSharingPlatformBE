package com.golfzonaca.officesharingplatform.repository.comment;

import com.golfzonaca.officesharingplatform.domain.Comment;
import com.golfzonaca.officesharingplatform.domain.Rating;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.web.comment.dto.CommentData;

import java.util.List;

public interface CommentRepository {
    void save(Comment comment);

    Comment findById(long commentId);

    List<Comment> findAllByRating(Rating rating);

    void update(Comment comment, CommentData data);

    void delete(Comment comment);

    Long countByUser(User user);

    List<Comment> findAllByUserWithPagination(User user, Integer page);

    List<Comment> findAllByRatingWithPagination(Rating rating, Integer page);
}
