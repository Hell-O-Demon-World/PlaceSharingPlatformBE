package com.golfzonaca.officesharingplatform.repository.answer;

import com.golfzonaca.officesharingplatform.domain.Answer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslAnswerRepository implements AnswerRepository {

    private final SpringJpaAnswerRepository jpaRepository;

    @Override
    public void save(Answer answer) {
        jpaRepository.save(answer);
    }

    @Override
    public Optional<Answer> findById(long answerId) {
        return jpaRepository.findById(answerId);
    }

    @Override
    public void delete(Answer answer) {
        jpaRepository.delete(answer);
    }
}
