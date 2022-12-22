package com.golfzonaca.officesharingplatform.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "MILEAGE_EARNING_USAGE_HISTORY")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MileageEarningUsage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne
    @JoinColumn(name = "MILEAGE_UPDATE_ID")
    private MileageUpdate mileageUpdate;
    @Column(name = "CURRENT_POINT")
    private Long currentPoint;
    @Column(name = "UPDATE_DATE")
    private LocalDateTime updateDate;
    @Column(name = "EXPIRE_DATE", nullable = false)
    private LocalDateTime expireDate;
    @Builder
    public MileageEarningUsage(MileageTransactionUsage mileageTransactionUsage, MileageUpdate mileageUpdate, Long currentPoint, LocalDateTime updateDate, LocalDateTime expireDate) {
        this.mileageUpdate = mileageUpdate;
        this.currentPoint = currentPoint;
        this.updateDate = updateDate;
        this.expireDate = expireDate;
    }

    public void updateCurrentDate(LocalDateTime currentDateTime) {
        this.updateDate = currentDateTime;
    }

    public void updateCurrentPoint(long usedPoint) {
        this.currentPoint += usedPoint;
    }

    public void minusPoint(Long minusPoint) {
        if (this.currentPoint - minusPoint < 0) {
            this.currentPoint = 0L;
        } else {
            this.currentPoint -= minusPoint;
        }
    }
}
