package com.golfzonaca.officesharingplatform.service.mypage.dto.mileage;

import com.golfzonaca.officesharingplatform.domain.type.MileagePaymentReason;
import com.golfzonaca.officesharingplatform.domain.type.MileageStatusType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class MileageHistoryDto {
    private String status;
    private String changePoint;
    private String info;
    private String issuer;
    private String updateDate;

    public MileageHistoryDto(MileageStatusType status, Long changePoint, String info, String issuer, LocalDateTime updateDate) {
        this.status = status.getDescription();
        this.changePoint = changePointStyle(changePoint, status);
        this.info = info;
        this.issuer = issuer;
        this.updateDate = changeDateStyle(updateDate);
    }

    private static String changeDateStyle(LocalDateTime dateTime) {
        String resultDate = "";
        resultDate = dateTime.getYear() + "." + dateTime.getMonth().getValue() + "." + dateTime.getDayOfMonth();
        return resultDate;
    }

    private static String changePointStyle(Long mileagePoint, MileageStatusType mileageStatusType) {
        String resultPoint = "";
        if (mileageStatusType.equals(MileageStatusType.EARNING)) {
            resultPoint += "+";
        } else if (mileageStatusType.equals(MileageStatusType.USE)) {
            resultPoint += "-";
        }
        return resultPoint += mileagePoint;
    }
}
