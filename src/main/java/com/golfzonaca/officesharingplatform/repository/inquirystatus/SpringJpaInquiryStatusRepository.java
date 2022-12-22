package com.golfzonaca.officesharingplatform.repository.inquirystatus;

import com.golfzonaca.officesharingplatform.domain.InquiryStatus;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaInquiryStatusRepository extends JpaRepository<InquiryStatus, Long> {
}
