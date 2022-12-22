package com.golfzonaca.officesharingplatform.repository.inquiry;

import com.golfzonaca.officesharingplatform.domain.Inquiry;
import com.golfzonaca.officesharingplatform.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.NoSuchElementException;

@Repository
@Transactional
@RequiredArgsConstructor
public class CustomInquiryRepository implements InquiryRepository {
    private final SpringJpaInquiryRepository jpaInquiryRepository;
    private final QueryInquiryRepository queryInquiryRepository;

    @Override
    public Inquiry save(Inquiry inquiry) {
        return jpaInquiryRepository.save(inquiry);
    }

    @Override
    public Inquiry findById(long inquiryId) {
        return jpaInquiryRepository.findById(inquiryId).orElseThrow(() -> new NoSuchElementException("존재하지 않는 문의입니다."));
    }

    @Override
    public List<Inquiry> findAllByUserWithPagination(User user, Integer page) {
        return queryInquiryRepository.findByUserWithPagination(user, page);
    }

}
