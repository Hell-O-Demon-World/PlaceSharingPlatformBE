package com.golfzonaca.officesharingplatform.repository.inquirystatus;

import com.golfzonaca.officesharingplatform.domain.InquiryStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslInquiryStatusRepository implements InquiryStatusRepository {
    private final SpringJpaInquiryStatusRepository jpaRepository;


    @Override
    public void save(InquiryStatus status) {
        jpaRepository.save(status);
    }

    @Override
    public Optional<InquiryStatus> findById(long inquiryStatusId) {
        return jpaRepository.findById(inquiryStatusId);
    }

    @Override
    public void update(InquiryStatus status, boolean data) {
        status.updateStatus(data);
    }

    @Override
    public void delete(InquiryStatus status) {
        jpaRepository.delete(status);
    }
}
