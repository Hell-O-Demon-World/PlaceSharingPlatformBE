package com.golfzonaca.officesharingplatform.repository.inquiry;

import com.golfzonaca.officesharingplatform.domain.Inquiry;
import com.golfzonaca.officesharingplatform.domain.User;

import java.util.List;

public interface InquiryRepository {
    Inquiry save(Inquiry inquiry);

    Inquiry findById(long inquiryId);

    List<Inquiry> findAllByUserWithPagination(User user, Integer page);
}
