package com.golfzonaca.officesharingplatform.service.reservation.validation;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Room;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.exception.*;
import com.golfzonaca.officesharingplatform.repository.reservation.ReservationRepository;
import com.golfzonaca.officesharingplatform.repository.room.RoomRepository;
import com.golfzonaca.officesharingplatform.repository.roomkind.RoomKindRepository;
import com.golfzonaca.officesharingplatform.web.formatter.TimeFormatter;
import com.golfzonaca.officesharingplatform.web.reservation.dto.process.ProcessReservationData;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.TextStyle;
import java.util.List;
import java.util.Locale;

@Component
@RequiredArgsConstructor
public class ReservationRequestValidation {

    private final RoomRepository roomRepository;
    private final RoomKindRepository roomKindRepository;
    private final ReservationRepository reservationRepository;

    public void validation(RoomType roomType, String date) {
        validRealDate(date);
        validRoomType(roomType);
    }

    public void validation(Place place, RoomType roomType, String date, String startTime) {
        validRealDate(date);
        validRealTime(Integer.parseInt(startTime));
        validRoomType(roomType);
        validTimeOfRoomType(roomType);
        validStartTime(TimeFormatter.toLocalTime(startTime), place.getPlaceStart(), place.getPlaceEnd(), TimeFormatter.toLocalDate(date));
        validBusinessTime(place, TimeFormatter.toLocalTime(startTime));
        validBusinessDay(place, TimeFormatter.toLocalDate(date));
    }

    public void validation(User user, Place place, ProcessReservationData data) {
        RoomType roomType = RoomType.getRoomType(data.getSelectedType().toUpperCase());
        if (!roomType.name().contains("OFFICE")) {
            validNotSameDay(data);
            validBusinessDay(place, data.getStartDate());
            validDuplicatedResStartAndEndTime(data);
            validResTimeBetweenPlaceOpeningTime(place, data.getStartTime(), data.getEndTime());
            validDuplicatedResForSameUser(user, data.getStartDate(), data.getStartTime(), data.getStartDate(), data.getEndTime());
        }
        validPastOfDateTime(LocalDateTime.of(data.getStartDate(), data.getStartTime()), LocalDateTime.of(data.getStartDate(), data.getEndTime()));
        validRestRoomForSelectedPlaceAndDateTime(place, roomType, data.getStartDate(), data.getStartTime(), data.getStartDate(), data.getEndTime());
        validSelectedDate(LocalDateTime.of(data.getStartDate(), data.getStartTime()), LocalDateTime.of(data.getEndDate(), data.getEndTime()), roomType);
    }

    private void validNotSameDay(ProcessReservationData data) {
        LocalDate startDate = data.getStartDate();
        LocalDate endDate = data.getEndDate();
        if (!startDate.equals(endDate)) {
            throw new InvalidReservationException("데스크와 회의실의 예약 날짜는 하루 단위로 입력해야 합니다.");
        }
    }

    private void validDuplicatedResStartAndEndTime(ProcessReservationData data) {
        if (data.getStartTime().equals(data.getEndTime())) {
            throw new DuplicatedReservationException("DuplicatedReservationException::: 시작시간과 종료시간이 같습니다.");
        }
    }

    private void validBusinessTime(Place place, LocalTime time) {
        if (place.getPlaceStart().isAfter(time) || place.getPlaceEnd().isBefore(time)) {
            throw new InvalidTimeException("InvalidTimeException::: 해당 시간은 영업시간에 포함되지 않습니다.");
        }
    }

    private void validRealTime(int time) {
        if (time < 0 || time >= 24) {
            throw new InvalidTimeException("InvalidTimeException::: 유효하지 않은 시간입니다. range = 0 ~ 23");
        }
    }

    private void validRoomType(RoomType roomType) {
        roomKindRepository.findByRoomType(roomType);
    }

    private void validTimeOfRoomType(RoomType roomType) {
        if (roomType.name().contains("OFFICE")) {
            throw new NonExistedRoomKindException("NonExistedRoomKindException::: 지원하지 않는 공간유형 입니다.");
        }
    }

    private void validBusinessDay(Place place, LocalDate date) {
        boolean businessDay = place.getOpenDays().contains(date.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.US));
        if (!businessDay) {
            throw new NotBusinessDayException("NotBusinessDayException::: 입력한 날짜는 영업일이 아닙니다.");
        }
        LocalDate realLocalDate = LocalDate.now();
        if (date.isBefore(realLocalDate)) {
            throw new NotBusinessDayException("NotBusinessDayException::: 지나간 날짜는 입력받을 수 없습니다.");
        }
    }

    private void validResTimeBetweenPlaceOpeningTime(Place place, LocalTime resStartTime, LocalTime resEndTime) {
        int startTime = resStartTime.getHour();
        int endTime = resEndTime.getHour();
        if (startTime == 0) {
            startTime = 24;
        }
        if (endTime == 0) {
            endTime = 24;
        }
        if (place.getPlaceStart().getHour() <= startTime && startTime < place.getPlaceEnd().getHour()) {
            if (place.getPlaceStart().getHour() >= endTime || endTime > place.getPlaceEnd().getHour()) {
                throw new NotBusinessTimeException("NotBusinessTimeException::: 입력된 시간은 영업 시간이 아닙니다.");
            }
        } else {
            throw new NotBusinessTimeException("NotBusinessTimeException::: 입력된 시간은 영업 시간이 아닙니다.");
        }
    }

    private void validStartTimeBeforeEndTime(LocalTime startTime, LocalTime endTime) {
        if (!(startTime.isBefore(endTime) || startTime.equals(endTime))) {
            throw new NotBusinessTimeException("StartTimeAfterEndTimeError::: 시작 시각이 종료 시각 이후입니다.");
        }
    }

    private void validStartTime(LocalTime startTime, LocalTime placeStartTime, LocalTime placeEndTime, LocalDate date) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime localDateTime = LocalDateTime.of(date, placeStartTime);
        if (localDateTime.isBefore(now)) {
            placeStartTime = now.toLocalTime();
        }

        if (!startTime.isBefore(placeEndTime)) {
            throw new NotBusinessTimeException("StartTimeAfterEndTimeError::: 선택된 시작 시각이 영업 종료 시각 이후입니다.");
        } else if (!startTime.isAfter(placeStartTime) && !startTime.equals(placeStartTime)) {
            throw new NotBusinessTimeException("StartTimeAfterEndTimeError::: 선택된 시작 시각이 사용 가능한 시작 시각 이전입니다.");
        }
    }

    private void validPastOfDateTime(LocalDateTime startDateTime, LocalDateTime endDateTime) {
        if (!(startDateTime.isAfter(LocalDateTime.now()) && endDateTime.isAfter(LocalDateTime.now()))) {
            throw new NotBusinessDayException("PastDateTimeError::: 예약일시가 현재보다 과거입니다.");
        }
    }

    private void validDuplicatedResForSameUser(User user, LocalDate startDate, LocalTime startTime, LocalDate endDate, LocalTime endTime) {
        if (!reservationRepository.findInResValid(user, startDate, startTime, endDate, endTime)) {
            throw new DuplicatedReservationException("DuplicatedResForUserError::: 선택하신 시간과 공간에 대한 예약 내역이 존재합니다.");
        }
    }

    private void validRestRoomForSelectedPlaceAndDateTime(Place place, RoomType selectedType, LocalDate startDate, LocalTime startTime, LocalDate endDate, LocalTime endTime) {
        List<Room> roomByPlaceAndRoomKind = roomRepository.findRoomByPlaceAndRoomKind(place, selectedType);

        if (roomByPlaceAndRoomKind.size() == 0) {
            throw new NonexistentRestRoomForSelectedPlaceAndDateTime("NonexistentRestRoomForSelectedPlaceAndDateTime::: 선택하신 시간과 공간에 대해 빈 " + selectedType.getDescription() + "이(가) 없습니다.");
        }
    }

    private void validRealDate(String selectedDate) {
        try {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            dateFormat.setLenient(false);
            dateFormat.parse(selectedDate);
        } catch (ParseException e) {
            throw new InvalidDateException("InvalidDateError::: 선택하신 날짜는 존재하지 않습니다.");
        }
    }

    public void validSelectedDate(LocalDateTime startDate, LocalDateTime endDate, RoomType roomType) {
        if (startDate.isAfter(endDate)) {
            throw new InvalidDateException("InvalidDateException::: 종료시간이 시작시간보다 빠릅니다.");
        }
        if (roomType.name().contains("OFFICE")) {
            if (startDate.getYear() == endDate.getYear() && startDate.getMonth() == endDate.getMonth() && startDate.getDayOfMonth() == endDate.getDayOfMonth()) {
                throw new InvalidDateException("InvalidDateException::: 예약 기간을 하루 이상 입력해주세요");
            }
        }
    }

    public boolean isOpenToday(Place findPlace, LocalTime now) {
        return (findPlace.getPlaceStart().equals(now) || findPlace.getPlaceStart().isBefore(now)) && findPlace.getPlaceEnd().isAfter(now);
    }

    public boolean isOpenDaysByDate(String[] openDays, LocalDate date) {
        boolean state = true;
        for (String d : openDays) {
            if (TimeFormatter.toDayOfTheWeek(date).equals(d)) {
                state = false;
                break;
            }
        }
        return state;
    }
}
