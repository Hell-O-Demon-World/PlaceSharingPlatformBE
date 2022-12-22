package com.golfzonaca.officesharingplatform.service.mileage;

import com.golfzonaca.officesharingplatform.domain.*;
import com.golfzonaca.officesharingplatform.domain.type.MileagePaymentReason;
import com.golfzonaca.officesharingplatform.domain.type.MileageStatusType;
import com.golfzonaca.officesharingplatform.repository.mileage.MileageRepository;
import com.golfzonaca.officesharingplatform.service.payment.MileageTimeSetter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class SpringJpaDslMileageService implements MileageService {
    private final MileageRepository mileageRepository;
    private final static long INITIAL_POINT = 0;

    @Override
    public Mileage join() {
        Mileage mileage = Mileage.builder()
                .point(INITIAL_POINT)
                .latestUpdateDate(MileageTimeSetter.currentDateTime())
                .build();
        Mileage saveMileage = mileageRepository.save(mileage);
        saveMileageUpdate(saveMileage, INITIAL_POINT, MileageStatusType.NEW_MEMBER);
        return mileage;
    }

    @Override
    public void savingFullPaymentMileage(Payment payment) {
        Mileage mileage = payment.getReservation().getUser().getMileage();
        long currentPayMileage = payment.getSavedMileage();
        MileageUpdate savedMileageUpdate = saveMileageUpdate(mileage, currentPayMileage, MileageStatusType.EARNING);
        saveMileagePaymentUpdate(payment, currentPayMileage, savedMileageUpdate, MileagePaymentReason.FULL_PAYMENT);
        saveMileageEarningUsage(currentPayMileage, savedMileageUpdate);

        mileage.addPoint(currentPayMileage);
    }

    private MileageUpdate saveMileageUpdate(Mileage mileage, long currentPayMileage, MileageStatusType mileageStatusType) {
        MileageUpdate mileageUpdate = MileageUpdate.builder()
                .mileage(mileage)
                .statusType(mileageStatusType)
                .updatePoint(currentPayMileage)
                .updateDate(MileageTimeSetter.currentDateTime())
                .build();
        return mileageRepository.save(mileageUpdate);
    }

    private void saveMileageEarningUsage(long currentPayMileage, MileageUpdate mileageUpdate) {
        MileageEarningUsage mileageEarningUsage = MileageEarningUsage.builder()
                .mileageUpdate(mileageUpdate)
                .currentPoint(currentPayMileage)
                .updateDate(MileageTimeSetter.currentDateTime())
                .expireDate(MileageTimeSetter.expiredDateTime())
                .build();
        mileageRepository.save(mileageEarningUsage);
    }

    private MileagePaymentUpdate saveMileagePaymentUpdate(Payment payment, long currentPayMileage, MileageUpdate savedMileageUpdate, MileagePaymentReason reason) {
        MileagePaymentUpdate mileagePaymentUpdate = MileagePaymentUpdate.builder()
                .mileageUpdate(savedMileageUpdate)
                .payment(payment)
                .updatePoint(currentPayMileage)
                .paymentReason(reason)
                .build();

        return mileageRepository.save(mileagePaymentUpdate);
    }

    @Override
    public void recoveryMileage(Mileage mileage, Payment payment) {
        long totalPlusPoint = 0L;
        MileagePaymentUpdate paymentMileage = mileageRepository.findMileageByPayment(payment);
        List<MileageTransactionUsage> transactionUsageMileageList = mileageRepository.findTransactionUsageMileageByPaymentMileage(paymentMileage);
        for (MileageTransactionUsage mileageTransactionUsage : transactionUsageMileageList) {
            MileageEarningUsage earningUsage = mileageTransactionUsage.getMileageEarningUsage();
            LocalDateTime expireDate = earningUsage.getExpireDate();
            long usedPoint = mileageTransactionUsage.getUsedPoint();
            if (MileageTimeSetter.currentDateTime().isBefore(expireDate)) {
                earningUsage.updateCurrentPoint(usedPoint);
                earningUsage.updateCurrentDate(MileageTimeSetter.currentDateTime());
                totalPlusPoint += usedPoint;
            }
        }
        MileageUpdate saveMileageUpdate = saveMileageUpdate(mileage, totalPlusPoint, MileageStatusType.EARNING);
        saveMileagePaymentUpdate(payment, totalPlusPoint, saveMileageUpdate, MileagePaymentReason.REFUND);
        mileage.addPoint(totalPlusPoint);
    }

    @Override
    public void payingMileage(Payment payment) {
        User user = payment.getReservation().getUser();
        Mileage findMileage = user.getMileage();
        long payMileage = payment.getPayMileage();
        MileageUpdate savedUpdateMileage = saveMileageUpdate(findMileage, payMileage, MileageStatusType.USE);
        MileagePaymentUpdate savedPaymentMileage = saveMileagePaymentUpdate(payment, payMileage, savedUpdateMileage, MileagePaymentReason.USE_MILEAGE);

        List<MileageEarningUsage> mileageEarningUsageList = mileageRepository.findAllMileageEarningUsageByMileage(findMileage);
        long remainMileagePoint = payMileage;
        for (MileageEarningUsage update : mileageEarningUsageList) {
            Long updatePoint = update.getCurrentPoint();
            if (updatePoint > 0) {
                long minusPoint = updatePoint;
                if (updatePoint <= remainMileagePoint) {
                    remainMileagePoint -= updatePoint;
                } else {
                    minusPoint = remainMileagePoint;
                    remainMileagePoint = 0;
                }
                saveAndUpdateMileage(savedPaymentMileage, update, minusPoint);
            }
            if (remainMileagePoint == 0) {
                break;
            }
        }
        findMileage.minusPoint(payMileage);
    }

    private void saveAndUpdateMileage(MileagePaymentUpdate mileageByPayment, MileageEarningUsage earningUsage, Long minusPoint) {
        earningUsage.minusPoint(minusPoint);
        earningUsage.updateCurrentDate(MileageTimeSetter.currentDateTime());
        MileageTransactionUsage mileageTransactionUsage = MileageTransactionUsage.builder()
                .mileagePaymentUpdate(mileageByPayment)
                .mileageEarningUsage(earningUsage)
                .usedPoint(minusPoint)
                .build();
        mileageRepository.save(mileageTransactionUsage);
    }
}
