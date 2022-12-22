package com.golfzonaca.officesharingplatform.repository.mileage.springdatajpa;

import com.golfzonaca.officesharingplatform.domain.MileageTransactionUsage;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaMileageTransactionUsageRepository extends JpaRepository<MileageTransactionUsage, Long> {

}
