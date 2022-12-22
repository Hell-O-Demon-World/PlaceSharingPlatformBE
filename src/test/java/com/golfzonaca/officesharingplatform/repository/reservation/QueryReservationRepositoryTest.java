package com.golfzonaca.officesharingplatform.repository.reservation;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.repository.place.PlaceRepository;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.Month;

@SpringBootTest
@Transactional
class QueryReservationRepositoryTest {
    @Autowired
    ReservationRepository reservationRepository;
    @Autowired
    QueryReservationRepository queryReservationRepository;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PlaceRepository placeRepository;

    @Test
    void findInResValid() {
        Long userId = 4L;
        User givenUser = userRepository.findById(userId);
        long placeId = 21L;
        Place givenPlace = placeRepository.findById(placeId);
        LocalDate startDate = LocalDate.of(2022, Month.DECEMBER,21);
        LocalTime startTime = LocalTime.of(18, 0);
        LocalDate endDate = LocalDate.of(2022, Month.DECEMBER,21);
        LocalTime endTime = LocalTime.of(22, 0);

        LocalDate startDate2 = LocalDate.of(2022, Month.DECEMBER,22);
        LocalTime startTime2 = LocalTime.of(18, 0);
        LocalDate endDate2 = LocalDate.of(2022, Month.DECEMBER,22);
        LocalTime endTime2 = LocalTime.of(22, 0);

        boolean inResValid = reservationRepository.findInResValid(givenUser
                , startDate, startTime, endDate, endTime);
        boolean inResBValid2 = queryReservationRepository.findResThatDay(givenUser, givenPlace, startDate, endDate).isEmpty();
        boolean inResValid2 = reservationRepository.findInResValid(givenUser
                , startDate, startTime, endDate, endTime);
        boolean inResBValid22 = queryReservationRepository.findResThatDay(givenUser, givenPlace, startDate2, endDate2).isEmpty();
        System.out.println("날짜비교(당일) = " + inResValid);
        System.out.println("날짜비교(당일) = " + inResBValid2);
        System.out.println("날짜비교(내일) = " + inResValid2);
        System.out.println("날짜비교(내일) = " + inResBValid22);
    }
}