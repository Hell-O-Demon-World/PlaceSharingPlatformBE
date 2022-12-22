package com.golfzonaca.officesharingplatform.web.validation;

import com.golfzonaca.officesharingplatform.domain.Reservation;
import com.golfzonaca.officesharingplatform.domain.type.FixStatus;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.exception.BindingResultErrorException;
import com.golfzonaca.officesharingplatform.exception.InvalidResCancelRequest;
import com.golfzonaca.officesharingplatform.repository.rating.RatingRepository;
import com.golfzonaca.officesharingplatform.repository.reservation.ReservationRepository;
import com.golfzonaca.officesharingplatform.repository.room.RoomRepository;
import com.golfzonaca.officesharingplatform.repository.roomkind.RoomKindRepository;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;

import java.util.Objects;

@Component
@RequiredArgsConstructor
public class RequestValidation {
    private final RoomRepository roomRepository;
    private final RoomKindRepository roomKindRepository;
    private final UserRepository userRepository;
    private final ReservationRepository reservationRepository;
    private final RatingRepository ratingRepository;

    public void bindingResultCheck(BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            for (ObjectError objectError : bindingResult.getAllErrors()) {
                String msg = objectError.getCode() + "ValidationError::: " + Objects.requireNonNull(objectError.getDefaultMessage());
                throw new BindingResultErrorException(msg);
            }
        }
    }

    public void validUser(Long userId) {
        userRepository.findById(userId);
    }

    public void validRoom(Long roomId) {
        roomRepository.findById(roomId);
    }

    public void validRoomType(RoomType roomType) {
        roomKindRepository.findByRoomType(roomType);
    }

    public void validReservation(Long reservationId) {
        Reservation reservation = reservationRepository.findById(reservationId);
        if (reservation.getFixStatus() == FixStatus.FIXED) {
            throw new InvalidResCancelRequest("취소할 수 없는 예약입니다");
        }
    }

    public void validRating(Long ratingId) {
        ratingRepository.findById(ratingId);
    }

    public void validUserAndReservation(Long userId, long reservationId) {
        reservationRepository.findByIdAndUserID(reservationId, userId);
    }
}
