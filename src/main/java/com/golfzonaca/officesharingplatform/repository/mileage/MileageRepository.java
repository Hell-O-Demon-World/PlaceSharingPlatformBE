package com.golfzonaca.officesharingplatform.repository.mileage;

import com.golfzonaca.officesharingplatform.domain.*;

import java.time.LocalDateTime;
import java.util.List;

public interface MileageRepository {
    Mileage save(Mileage mileage);
    MileageUpdate save(MileageUpdate mileageUpdate);
    MileagePaymentUpdate save(MileagePaymentUpdate mileagePaymentUpdate);
    MileageTransactionUsage save(MileageTransactionUsage mileageTransactionUsage);
    MileageEarningUsage save(MileageEarningUsage mileageEarningUsage);
    Mileage findByID(Long id);
    MileagePaymentUpdate findMileageByPayment(Payment payment);
    List<MileageTransactionUsage> findTransactionUsageMileageByPaymentMileage(MileagePaymentUpdate mileagePaymentUpdate);
    Mileage findByUser(User user);
    List<MileageUpdate> findMileageUpdateAll();

    List<MileageUpdate> findAllMileageUpdateByMileage(Mileage findMileage, Long page, Long items);
    List<MileageUpdate> findAllMileageUpdateByMileage(Mileage findMileage);

    MileagePaymentUpdate findMileagePaymentByMileageUpdate(MileageUpdate mileageUpdate);

    List<MileageEarningUsage> findAllMileageEarningUsageByMileage(Mileage mileage);
}
