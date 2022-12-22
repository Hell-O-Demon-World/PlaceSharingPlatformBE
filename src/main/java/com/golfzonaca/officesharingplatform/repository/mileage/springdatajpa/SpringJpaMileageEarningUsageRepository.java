package com.golfzonaca.officesharingplatform.repository.mileage.springdatajpa;

import com.golfzonaca.officesharingplatform.domain.MileageEarningUsage;
import com.golfzonaca.officesharingplatform.domain.MileageTransactionUsage;
import com.golfzonaca.officesharingplatform.domain.MileageUpdate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SpringJpaMileageEarningUsageRepository extends JpaRepository<MileageEarningUsage, Long> {
    List<MileageEarningUsage> findAllByMileageUpdate(MileageUpdate mileageUpdate);
}
