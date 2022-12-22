package com.golfzonaca.officesharingplatform.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "mileage_transaction_usage_history")
@NoArgsConstructor
@Getter
@AllArgsConstructor
public class MileageTransactionUsage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @OneToOne
    @JoinColumn(name = "MILEAGE_PAYMENT_UPDATE_ID")
    private MileagePaymentUpdate mileagePaymentUpdate;
    @OneToOne
    @JoinColumn(name = "MILEAGE_EARNING_USAGE_ID")
    private MileageEarningUsage mileageEarningUsage;
    @Column(name = "USED_POINT")
    private long usedPoint;
    @Builder
    public MileageTransactionUsage(MileagePaymentUpdate mileagePaymentUpdate, MileageEarningUsage mileageEarningUsage , long usedPoint) {
        this.mileagePaymentUpdate = mileagePaymentUpdate;
        this.usedPoint = usedPoint;
        this.mileageEarningUsage = mileageEarningUsage;
    }
}
