package com.golfzonaca.officesharingplatform.repository.address;

import com.golfzonaca.officesharingplatform.domain.Address;

import java.util.List;

public interface AddressRepository {
    List<Address> findByAddressId(List addressIdList);
}
