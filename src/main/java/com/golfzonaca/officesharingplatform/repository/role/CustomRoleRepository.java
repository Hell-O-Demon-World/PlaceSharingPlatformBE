package com.golfzonaca.officesharingplatform.repository.role;

import com.golfzonaca.officesharingplatform.domain.Role;
import com.golfzonaca.officesharingplatform.domain.type.RoleType;
import com.golfzonaca.officesharingplatform.exception.NonExistedRoleTypeException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Transactional
@Repository
@RequiredArgsConstructor
public class CustomRoleRepository implements RoleRepository {
    private final SpringDataJpaRoleRepository jpaRoleRepository;

    @Override
    public Role findByRoleType(RoleType roleType) {
        return jpaRoleRepository.findByRoleType(roleType).orElseThrow(()->new NonExistedRoleTypeException("NonExistedRoleTypeException::: 존재하지 않는 역할 입니다."));
    }
}
