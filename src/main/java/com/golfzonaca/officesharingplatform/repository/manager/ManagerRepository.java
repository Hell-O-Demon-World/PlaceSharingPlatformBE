package com.golfzonaca.officesharingplatform.repository.manager;

import com.golfzonaca.officesharingplatform.domain.Manager;

import java.util.Optional;

public interface ManagerRepository {
    void save(Manager manager);

    Optional<Manager> findById(long managerId);

//    void update(Manager manager);

    void delete(Manager manager);
}
