package com.golfzonaca.officesharingplatform.repository.company;

import com.golfzonaca.officesharingplatform.domain.Company;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaCompanyRepository extends JpaRepository<Company, Long> {
}
