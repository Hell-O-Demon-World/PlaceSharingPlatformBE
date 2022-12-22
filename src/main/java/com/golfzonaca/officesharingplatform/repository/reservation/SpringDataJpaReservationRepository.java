package com.golfzonaca.officesharingplatform.repository.reservation;

import com.golfzonaca.officesharingplatform.domain.Reservation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SpringDataJpaReservationRepository extends JpaRepository<Reservation, Long> {
    Optional<Reservation> findFirstByIdAndUserId(Long reservationId, Long userId);
}
