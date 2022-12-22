package com.golfzonaca.officesharingplatform.repository.mileage;

import com.golfzonaca.officesharingplatform.domain.*;
import com.golfzonaca.officesharingplatform.exception.NonExistedMileageException;
import com.golfzonaca.officesharingplatform.repository.mileage.querydsl.QueryDslMileageEarningUsageRepository;
import com.golfzonaca.officesharingplatform.repository.mileage.querydsl.QueryDslMileagePaymentUpdateRepository;
import com.golfzonaca.officesharingplatform.repository.mileage.querydsl.QueryDslMileageUpdateRepository;
import com.golfzonaca.officesharingplatform.repository.mileage.springdatajpa.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
@RequiredArgsConstructor
public class JpaMileageRepository implements MileageRepository {
    private final SpringJpaMileageRepository jpaMileageRepository;
    private final SpringJpaMileageUpdateRepository jpaMileageUpdateRepository;
    private final SpringJpaMileageEarningUsageRepository jpaMileageEarningUsageRepository;
    private final SpringJpaMileagePaymentRepository jpaMileagePaymentRepository;
    private final SpringJpaMileageTransactionUsageRepository jpaMileageTransactionUsageRepository;
    private final QueryDslMileageUpdateRepository queryDslMileageUpdateRepository;
    private final QueryDslMileagePaymentUpdateRepository queryDslMileagePaymentUpdateRepository;
    private final QueryDslMileageEarningUsageRepository queryDslMileageEarningUsageRepository;

    @Override
    public Mileage save(Mileage mileage) {
        return jpaMileageRepository.save(mileage);
    }

    @Override
    public MileageUpdate save(MileageUpdate mileageUpdate) {
        return jpaMileageUpdateRepository.save(mileageUpdate);
    }

    @Override
    public MileagePaymentUpdate save(MileagePaymentUpdate mileagePaymentUpdate) {
        return jpaMileagePaymentRepository.save(mileagePaymentUpdate);
    }

    @Override
    public MileageTransactionUsage save(MileageTransactionUsage mileageTransactionUsage) {
        return jpaMileageTransactionUsageRepository.save(mileageTransactionUsage);
    }

    @Override
    public MileageEarningUsage save(MileageEarningUsage mileageEarningUsage) {
        return jpaMileageEarningUsageRepository.save(mileageEarningUsage);
    }

    @Override
    public Mileage findByID(Long id) {
        return jpaMileageRepository.findById(id).orElseThrow(() -> new NonExistedMileageException("NonExistedMileageException::: 마일리지가 존재하지 않습니다."));
    }

    @Override
    public MileagePaymentUpdate findMileageByPayment(Payment payment) {
        return queryDslMileagePaymentUpdateRepository.findFirstMileageByPayment(payment).orElseThrow(() -> new RuntimeException("No MileagePaymentUpdate"));
    }

    @Override
    public List<MileageTransactionUsage> findTransactionUsageMileageByPaymentMileage(MileagePaymentUpdate mileagePaymentUpdate) {
        return queryDslMileagePaymentUpdateRepository.findTransactionUsageMileageByPaymentMileage(mileagePaymentUpdate);
    }
    @Override
    public Mileage findByUser(User user) {
        return jpaMileageRepository.findById(user.getId()).orElseThrow(() -> new NonExistedMileageException("NonExistedMileageException:: 마일리지가 존재하지 않습니다."));
    }

    @Override
    public List<MileageUpdate> findMileageUpdateAll() {
        return jpaMileageUpdateRepository.findAll();
    }

    @Override
    public List<MileageUpdate> findAllMileageUpdateByMileage(Mileage mileage, Long page, Long items) {
        return queryDslMileageUpdateRepository.findByMileageWithPagination(mileage, page, items);
    }

    @Override
    public List<MileageUpdate> findAllMileageUpdateByMileage(Mileage mileage) {
        return jpaMileageUpdateRepository.findAllByMileage(mileage);
    }

    @Override
    public MileagePaymentUpdate findMileagePaymentByMileageUpdate(MileageUpdate mileageUpdate) {
        return queryDslMileagePaymentUpdateRepository.findFirstMileageByUpdate(mileageUpdate);
    }

    @Override
    public List<MileageEarningUsage> findAllMileageEarningUsageByMileage(Mileage mileage) {
        return queryDslMileageEarningUsageRepository.findAllByMileage(mileage);
    }
}
