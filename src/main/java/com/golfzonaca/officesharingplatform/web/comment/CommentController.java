package com.golfzonaca.officesharingplatform.web.comment;

import com.golfzonaca.officesharingplatform.annotation.TokenUserId;
import com.golfzonaca.officesharingplatform.service.comment.CommentService;
import com.golfzonaca.officesharingplatform.web.comment.dto.CommentData;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class CommentController {

    private final CommentService commentService;

    @PostMapping("/{ratingId}/comment/add")
    public Map<String, JsonObject> saveComment(@TokenUserId Long userId, @PathVariable Long ratingId, @Validated @RequestBody CommentData data, BindingResult bindingResult) {
        return commentService.save(userId, ratingId, data);
    }

    @GetMapping("/comment/{commentId}/delete")
    public Map<String, JsonObject> deleteComment(@TokenUserId Long userId, @PathVariable long commentId) {
        return commentService.delete(userId, commentId);
    }
}
