package com.golfzonaca.officesharingplatform.batch;

import com.golfzonaca.officesharingplatform.service.mypage.MyPageService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

@Component
@Transactional
@RequiredArgsConstructor
public class BatchManager {
    private final MyPageService myPageService;

    public void reservationClear(Long userId) {
        myPageService.clearPreoccupiedReservation(userId);
        myPageService.forceFixReservationStarted(userId);
    }
}
