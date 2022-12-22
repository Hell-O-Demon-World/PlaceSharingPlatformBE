package com.golfzonaca.officesharingplatform.repository.answer;

import com.golfzonaca.officesharingplatform.domain.Answer;

import java.util.Optional;

public interface AnswerRepository {
    void save(Answer answer);

    Optional<Answer> findById(long answerId);
    
    void delete(Answer answer);
}
