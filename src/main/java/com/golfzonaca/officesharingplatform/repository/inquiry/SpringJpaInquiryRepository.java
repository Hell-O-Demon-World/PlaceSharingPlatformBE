package com.golfzonaca.officesharingplatform.repository.inquiry;

import com.golfzonaca.officesharingplatform.domain.Inquiry;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaInquiryRepository extends JpaRepository<Inquiry, Long> {
}
