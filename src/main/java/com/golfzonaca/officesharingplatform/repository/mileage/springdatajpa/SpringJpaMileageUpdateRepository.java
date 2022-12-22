package com.golfzonaca.officesharingplatform.repository.mileage.springdatajpa;

import com.golfzonaca.officesharingplatform.domain.Mileage;
import com.golfzonaca.officesharingplatform.domain.MileageUpdate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDate;
import java.util.List;

public interface SpringJpaMileageUpdateRepository extends JpaRepository<MileageUpdate, Long> {
    MileageUpdate save(MileageUpdate mileageUpdate);
    List<MileageUpdate> findAllByMileage(Mileage mileage);
}
