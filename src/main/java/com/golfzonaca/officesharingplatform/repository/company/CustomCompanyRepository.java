package com.golfzonaca.officesharingplatform.repository.company;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
@RequiredArgsConstructor
public class CustomCompanyRepository implements CompanyRepository {

    private final SpringJpaCompanyRepository jpaRepository;
    private final QueryCompanyRepository queryCompanyRepository;

}
