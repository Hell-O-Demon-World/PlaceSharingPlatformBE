package com.golfzonaca.officesharingplatform.repository.reservation;

import com.golfzonaca.officesharingplatform.domain.Reservation;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@SpringBootTest
@Transactional
public class CustomReservationRepositoryTest {
    @Autowired
    ReservationRepository reservationRepository;

    @Test
    void findAllByPlaceIdAndRoomTypeAndDate2() {
        LocalDate localDate = LocalDate.of(2023, 3, 18);

        List<Reservation> allByPlaceIdAndRoomTypeAndDate2 = reservationRepository.findAllByPlaceIdAndRoomTypeAndDate(9L, RoomType.MEETINGROOM20, localDate);
        for (Reservation reservation : allByPlaceIdAndRoomTypeAndDate2) {
            System.out.println("reservation = " + reservation.getId());
        }
    }

}