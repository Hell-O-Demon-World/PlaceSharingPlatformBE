package com.golfzonaca.officesharingplatform.service.comment;

import com.golfzonaca.officesharingplatform.web.comment.dto.CommentData;
import com.google.gson.JsonObject;

import java.util.Map;

public interface CommentService {

    Map<String, JsonObject> save(Long userId, Long ratingId, CommentData data);

    Map<String, JsonObject> delete(Long userId, long commentId);
}
