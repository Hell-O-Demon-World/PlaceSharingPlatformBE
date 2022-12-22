package com.golfzonaca.officesharingplatform.repository.mileage.springdatajpa;

import com.golfzonaca.officesharingplatform.domain.Mileage;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SpringJpaMileageRepository extends JpaRepository<Mileage, Long> {
    Mileage save(Mileage mileage);

    Optional<Mileage> findById(Long id);
}
