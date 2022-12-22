package com.golfzonaca.officesharingplatform.repository.address;

import com.golfzonaca.officesharingplatform.domain.Address;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
@RequiredArgsConstructor
public class CustomAddressRepository implements AddressRepository {

    private final SpringJpaAddressRepository jpaRepository;

    private final QueryAddressRepository queryRepository;

    @Override
    public List<Address> findByAddressId(List addressIdList) {
        return null;
    }
}
