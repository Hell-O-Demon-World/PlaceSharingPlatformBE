package com.golfzonaca.officesharingplatform.repository.inquirystatus;

import com.golfzonaca.officesharingplatform.domain.InquiryStatus;

import java.util.Optional;

public interface InquiryStatusRepository {
    void save(InquiryStatus status);

    Optional<InquiryStatus> findById(long inquiryStatusId);

    void update(InquiryStatus status, boolean updateStatus);

    void delete(InquiryStatus status);

}
