package com.golfzonaca.officesharingplatform.repository.manager;

import com.golfzonaca.officesharingplatform.domain.Manager;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaManagerRepository extends JpaRepository<Manager, Long> {
}
