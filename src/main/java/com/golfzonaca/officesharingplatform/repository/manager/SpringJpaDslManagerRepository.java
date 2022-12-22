package com.golfzonaca.officesharingplatform.repository.manager;

import com.golfzonaca.officesharingplatform.domain.Manager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslManagerRepository implements ManagerRepository {
    private final SpringJpaManagerRepository jpaRepository;


    @Override
    public void save(Manager manager) {
        jpaRepository.save(manager);
    }

    @Override
    public Optional<Manager> findById(long managerId) {
        return jpaRepository.findById(managerId);
    }

    /*
        @Override
        public void update(Manager manager) {
        }
    */
    @Override
    public void delete(Manager manager) {
        jpaRepository.delete(manager);
    }
}
