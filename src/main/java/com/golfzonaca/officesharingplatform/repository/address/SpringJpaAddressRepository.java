package com.golfzonaca.officesharingplatform.repository.address;

import com.golfzonaca.officesharingplatform.domain.Address;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringJpaAddressRepository extends JpaRepository<Address, Long> {
}
