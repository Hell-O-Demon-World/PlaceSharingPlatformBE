package com.golfzonaca.officesharingplatform.service.comment;

import com.golfzonaca.officesharingplatform.domain.Comment;
import com.golfzonaca.officesharingplatform.domain.Rating;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.repository.comment.CommentRepository;
import com.golfzonaca.officesharingplatform.repository.place.PlaceRepository;
import com.golfzonaca.officesharingplatform.repository.rating.RatingRepository;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import com.golfzonaca.officesharingplatform.service.comment.dto.CommentDto;
import com.golfzonaca.officesharingplatform.web.comment.dto.CommentData;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslCommentService implements CommentService {
    private final CommentRepository commentRepository;
    private final UserRepository userRepository;
    private final PlaceRepository placeRepository;
    private final RatingRepository ratingRepository;

    @Override
    public Map<String, JsonObject> save(Long userId, Long ratingId, CommentData data) {
        User user = userRepository.findById(userId);
        Rating rating = ratingRepository.findById(ratingId);
        commentRepository.save(new Comment(rating, data.getContext(), user, LocalDateTime.now()));
        return putCommentDataByRating(rating, 1);
    }

    @Override
    public Map<String, JsonObject> delete(Long userId, long commentId) {
        Comment comment = commentRepository.findById(commentId);
        Rating rating = comment.getRating();
        if (userRepository.findById(userId) != comment.getWriter()) {
            throw new IllegalArgumentException("해당 댓글 삭제에 대한 권한이 없습니다.");
        }
        commentRepository.delete(comment);
        return putCommentDataByRating(rating, 1);
    }

    private Map<String, JsonObject> putCommentDataByRating(Rating rating, Integer page) {
        Gson gson = new Gson();
        Map<String, JsonObject> commentDataMap = new LinkedHashMap<>();
        commentDataMap.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) rating.getCommentList().size() / 8))).getAsJsonObject());
        Map<String, JsonObject> commentData = processingCommentDataByRating(rating, page);
        commentDataMap.put("commentData", gson.toJsonTree(commentData).getAsJsonObject());
        return commentDataMap;
    }

    @NotNull
    private Map<String, JsonObject> processingCommentDataByRating(Rating rating, Integer commentpage) {
        Gson gson = new Gson();
        Map<String, JsonObject> commentData = new LinkedHashMap<>();
        for (int i = 0; i < commentRepository.findAllByRatingWithPagination(rating, commentpage).size(); i++) {
            Comment comment = commentRepository.findAllByRatingWithPagination(rating, commentpage).get(i);
            CommentDto src = new CommentDto(processingUserIdentification(comment.getWriter()), comment.getText(), comment.getDateTime().toLocalDate().toString(), comment.getDateTime().toLocalTime().toString());
            if (i == 0) {
                src.processingWrittenTime(comment.getDateTime().toLocalTime().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
            }
            commentData.put(String.valueOf(i), gson.toJsonTree(src).getAsJsonObject());
        }
        return commentData;
    }

    private String processingUserIdentification(User user) {
        String username = user.getUsername();
        String email = user.getEmail();
        int startMailDomain = email.lastIndexOf("@");
        String mailId = email.substring(0, startMailDomain);
        String mailDomain = email.substring(startMailDomain + 1);
        if (mailId.length() <= 4) {
            mailId = mailId + "***";
        } else {
            mailId = mailId.substring(0, 3) + "***";
        }
        mailDomain = mailDomain.charAt(0) + "*****";
        return username + "(" + mailId + mailDomain + ")";
    }
}
