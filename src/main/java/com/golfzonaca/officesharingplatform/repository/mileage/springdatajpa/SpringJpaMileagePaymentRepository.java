package com.golfzonaca.officesharingplatform.repository.mileage.springdatajpa;

import com.golfzonaca.officesharingplatform.domain.MileagePaymentUpdate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaMileagePaymentRepository extends JpaRepository<MileagePaymentUpdate, Long> {
    MileagePaymentUpdate save(MileagePaymentUpdate mileagePaymentUpdate);
}
