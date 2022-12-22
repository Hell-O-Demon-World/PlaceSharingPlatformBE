package com.golfzonaca.officesharingplatform.repository.comment;

import com.golfzonaca.officesharingplatform.domain.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaCommentRepository extends JpaRepository<Comment, Long> {
}
