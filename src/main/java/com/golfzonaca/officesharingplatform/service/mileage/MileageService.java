package com.golfzonaca.officesharingplatform.service.mileage;

import com.golfzonaca.officesharingplatform.domain.Mileage;
import com.golfzonaca.officesharingplatform.domain.Payment;

public interface MileageService {
    Mileage join();
    void savingFullPaymentMileage(Payment payment);
    void recoveryMileage(Mileage mileage, Payment payment);
    void payingMileage(Payment payment);
}
