package com.golfzonaca.officesharingplatform.service.reservation;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.Reservation;
import com.golfzonaca.officesharingplatform.domain.Room;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.domain.type.FixStatus;
import com.golfzonaca.officesharingplatform.domain.type.ReservationStatus;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.domain.type.dateformat.DateTimeFormat;
import com.golfzonaca.officesharingplatform.exception.DuplicatedReservationException;
import com.golfzonaca.officesharingplatform.repository.place.PlaceRepository;
import com.golfzonaca.officesharingplatform.repository.reservation.ReservationRepository;
import com.golfzonaca.officesharingplatform.repository.room.RoomRepository;
import com.golfzonaca.officesharingplatform.service.reservation.dto.ReservedRoom;
import com.golfzonaca.officesharingplatform.service.reservation.validation.ReservationRequestValidation;
import com.golfzonaca.officesharingplatform.web.formatter.TimeFormatter;
import com.golfzonaca.officesharingplatform.web.reservation.dto.process.ProcessReservationData;
import com.golfzonaca.officesharingplatform.web.reservation.dto.response.ReservationResponseData;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Month;
import java.util.*;

@Slf4j
@Transactional
@Service
@RequiredArgsConstructor
public class JpaReservationService implements ReservationService {
    private final ReservationRepository reservationRepository;
    private final RoomRepository roomRepository;
    private final PlaceRepository placeRepository;
    private final ReservationRequestValidation reservationRequestValidation;

    @Override
    public List<ReservationResponseData> getReservationResponseData(Place findPlace, RoomType roomType, String inputDate) throws IOException {
        LocalDateTime selectedStartDateTime = LocalDateTime.of(TimeFormatter.toLocalDate(inputDate), LocalTime.now());
        LocalDateTime selectedEndDateTime = LocalDateTime.of(TimeFormatter.toLocalDate(inputDate).plusYears(1), LocalTime.of(23, 59));
        return getTotalDayData(findPlace, roomType, selectedStartDateTime, selectedEndDateTime);
    }

    private List<ReservationResponseData> getTotalDayData(Place findPlace, RoomType roomType, LocalDateTime startDateTime, LocalDateTime endDateTime) throws IOException {

        List<ReservationResponseData> resultList = new ArrayList<>();
        String[] openDays = findPlace.getOpenDays().split(", ");
        int startYear = startDateTime.getYear();
        int endYear = endDateTime.getYear();
        List<Integer> years = getTotalYears(startYear, endYear);

        for (Integer year : years) {
            Month startMonth = startDateTime.getMonth();
            Month endMonth = endDateTime.getMonth();
            if (startYear != endYear) {
                if (startYear == year) {
                    endMonth = Month.of(12);
                } else if (endYear == year) {
                    startMonth = Month.of(1);
                } else {
                    startMonth = Month.of(1);
                    endMonth = Month.of(12);
                }
            }
            List<Month> months = getTotalMonth(startMonth, endMonth);
            for (Month month : months) {
                int startDay = startDateTime.getDayOfMonth();
                int endDay = endDateTime.getDayOfMonth();
                Calendar cal = Calendar.getInstance();
                if (month.equals(startMonth) && year.equals(startYear)) {
                    cal.set(year, month.getValue() - 1, startDay);
                    endDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
                } else if (month.equals(endMonth) && year.equals(endYear)) {
                    startDay = 1;
                    cal.set(year, month.getValue() - 1, startDay);
                } else {
                    startDay = 1;
                    cal.set(year, month.getValue() - 1, startDay);
                    endDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
                }
                for (int day = startDay; day < endDay + 1; day++) {
                    LocalDateTime date = LocalDateTime.of(year, month, day, findPlace.getPlaceStart().getHour(), findPlace.getPlaceEnd().getHour());
                    LocalTime startTime = getStartTime(startDateTime, date);
                    date = LocalDateTime.of(date.toLocalDate(), startTime);
                    boolean state;
                    TimeStates timeStates = TimeStates.of();
                    if (roomType.toString().contains("OFFICE")) {
                        state = getOfficeStateThatDate(findPlace.getId(), roomType, date.toLocalDate());
                    } else if (reservationRequestValidation.isOpenDaysByDate(openDays, date.toLocalDate())) {
                        state = false;
                        timeStates = TimeStates.allFalse();
                    } else {
                        List<Room> roomByPlaceIdAndRoomType = roomRepository.findRoomByPlaceIdAndRoomType(findPlace.getId(), roomType);
                        List<Reservation> findReservationList = reservationRepository.findAllByPlaceIdAndRoomTypeAndDate(findPlace.getId(), roomType, date.toLocalDate());
                        Map<Integer, ReservedRoom> reservedRoomMap = getReservedRoomMap(findPlace, findReservationList, roomByPlaceIdAndRoomType, date.toLocalDate());
                        state = !isFullReservation(findPlace, reservedRoomMap);
                        timeStates = getTimeStateOfDay(date, endDateTime, reservedRoomMap);
                    }
                    resultList.add(ReservationResponseData.builder().state(state).productType(roomType).date(DateTimeFormat.of(year, month, day, timeStates)).build());
                }
            }
        }
        return resultList;
    }

    private static LocalTime getStartTime(LocalDateTime startDateTime, LocalDateTime date) {
        LocalTime startTime = LocalTime.of(0, 0);
        if (date.toLocalDate().isEqual(startDateTime.toLocalDate())) {
            startTime = LocalTime.now().plusHours(1);
        }
        return startTime;
    }

    private TimeStates getTimeStateOfDay(LocalDateTime startDateTime, LocalDateTime endDateTime, Map<Integer, ReservedRoom> reservedRoomMap) throws IOException {
        TimeStates resultTimeStates = TimeStates.of();
        resultTimeStates.updateStartAndEndDateTime(startDateTime, endDateTime);

        for (int time = startDateTime.getHour(); time < endDateTime.getHour(); time++) {
            for (int i = 0; i < reservedRoomMap.size(); i++) {
                ReservedRoom reservedRoom = reservedRoomMap.get(i);
                resultTimeStates.replace(time, reservedRoom.getTimeState(time));
                if (reservedRoom.getTimeState(time)) {
                    break;
                }
            }
        }

        return resultTimeStates;
    }

    private boolean getOfficeStateThatDate(Long placeId, RoomType roomType, LocalDate date) {
        return !existReservationThatDay(placeId, roomType, date);
    }

    private List<Integer> getTotalYears(int startYear, int endYear) {
        List<Integer> result = new ArrayList<>();
        for (int i = startYear; i < endYear + 1; i++) {
            result.add(i);
        }
        return result;
    }

    private List<Month> getTotalMonth(Month startMonth, Month endMonth) {
        List<Month> result = new ArrayList<>();
        if (startMonth.equals(endMonth)) {
            result.add(startMonth);
        } else {
            for (int i = startMonth.getValue(); i < endMonth.getValue() + 1; i++) {
                result.add(Month.of(i));
            }
        }
        return result;
    }

    @Override
    public Boolean existReservationThatDay(Long placeId, RoomType roomType, LocalDate date) {
        return reservationRepository.findByPlaceIdAndRoomTypeAndDate(placeId, roomType, date).isPresent();
    }

    @Override
    public List<Integer> findAvailableTimes(Long placeId, RoomType selectedType, LocalDate date, LocalTime startTime) {
        Place findPlace = placeRepository.findById(placeId);

        return getTimeList(findPlace, selectedType, date, startTime);
    }

    private List<Integer> getTimeList(Place findPlace, RoomType selectedRoomType, LocalDate selectedDate, LocalTime selectedStartTime) {
        List<Room> reservedRoomList = roomRepository.findRoomByPlaceIdAndRoomType(findPlace.getId(), selectedRoomType);
        List<Reservation> findReservationList = reservationRepository.findAllByPlaceIdAndRoomTypeAndDate(findPlace.getId(), selectedRoomType, selectedDate);

        int totalReservationCount = reservedRoomList.size();
        int beforeReservationCount = countBeforeReservationList(findReservationList);

        LocalTime startTime = findPlace.getPlaceStart();
        LocalTime endTime = findPlace.getPlaceEnd();
        if (!hasFullReservation(totalReservationCount, beforeReservationCount)) {
            Map<Integer, ReservedRoom> reservedRoomMap = getReservedRoomMap(findPlace, findReservationList, reservedRoomList, selectedDate);
            return getResultList(findPlace, selectedStartTime.getHour(), reservedRoomMap);
        } else {
            return parsingMapToList(new ReservedRoom(0L, startTime, endTime, selectedDate).getTimeStates());
        }
    }

    private boolean isFullReservation(Place findPlace, Map<Integer, ReservedRoom> reservedRoomMap) {
        boolean result = true;

        int startTime = findPlace.getPlaceStart().plusHours(1).getHour();
        int endTime = findPlace.getPlaceEnd().getHour();
        for (int i = 0; i < reservedRoomMap.size(); i++) {
            ReservedRoom reservedRoom = reservedRoomMap.get(i);
            for (int j = startTime; j < endTime; j++) {
                if (reservedRoom.getTimeState(j)) {
                    result = false;
                    break;
                }
            }
            if (!result) {
                break;
            }
        }
        return result;
    }

    private List<Integer> getResultList(Place findPlace, int selectedStartTime, Map<Integer, ReservedRoom> reservedRoomMap) {
        int plusMaxPointer = selectedStartTime;
        int minusMinPointer = selectedStartTime;
        List<Boolean> onlyOneStatus = new ArrayList<>();

        for (int i = 0; i < reservedRoomMap.size(); i++) {
            ReservedRoom reservedRoom = reservedRoomMap.get(i);
            int plusPointer = selectedStartTime;
            int minusPointer = selectedStartTime;
            if (isBeforeTimeZeroAfterTimeFalse(selectedStartTime, reservedRoom) || isBeforeFalseAfterFalse(selectedStartTime, reservedRoom)) {
                onlyOneStatus.add(true);
            }
            if (!(plusMaxPointer == findPlace.getPlaceEnd().getHour())) {
                for (int j = selectedStartTime; j < findPlace.getPlaceEnd().getHour() - 1; j++) {
                    if (reservedRoom.getTimeState(j) && reservedRoom.getTimeState(j + 1)) {
                        plusPointer = j + 1;
                    } else {
                        break;
                    }
                }
                if (plusPointer > plusMaxPointer) {
                    plusMaxPointer = plusPointer;
                }
            }
            if (!(minusMinPointer == findPlace.getPlaceStart().getHour())) {
                for (int j = selectedStartTime; j > findPlace.getPlaceStart().getHour(); j--) {
                    if (reservedRoom.getTimeState(j) && reservedRoom.getTimeState(j - 1)) {
                        minusPointer = j - 1;
                    } else {
                        break;
                    }
                }
                if (minusPointer < minusMinPointer) {
                    minusMinPointer = minusPointer;
                }
            }
        }

        List<Integer> result = new ArrayList<>();

        if (onlyOneStatus.size() <= reservedRoomMap.size() && plusMaxPointer - minusMinPointer < 1 ) {
            result.add(plusMaxPointer);
        } else if (minusMinPointer != plusMaxPointer) {
            for (int i = minusMinPointer; i < plusMaxPointer + 1; i++) {
                result.add(i);
            }
        }
        return result;
    }

    private boolean isBeforeTimeZeroAfterTimeFalse(int selectedStartTime, ReservedRoom reservedRoom) {
        return selectedStartTime == 0 && reservedRoom.getTimeState(selectedStartTime) && !reservedRoom.getTimeState(selectedStartTime + 1);
    }

    private boolean isBeforeFalseAfterFalse(int selectedStartTime, ReservedRoom reservedRoom) {
        return !reservedRoom.getTimeState(selectedStartTime - 1) && reservedRoom.getTimeState(selectedStartTime) && !reservedRoom.getTimeState(selectedStartTime + 1);
    }

    @Override
    public Reservation saveReservation(User user, Place place, ProcessReservationData data) {
        LocalTime startTime = data.getStartTime();
        LocalTime endTime = data.getEndTime();
        LocalDate date = data.getStartDate();
        LocalDate endDate = data.getEndDate();
        RoomType selectedType = RoomType.getRoomType(data.getSelectedType());
        Room resultRoom;
        if (selectedType.toString().toUpperCase().contains("OFFICE")) {
            resultRoom = getResultRoom(place, date, endDate, selectedType);
        } else {
            resultRoom = getResultRoom(place, startTime, endTime, date, selectedType);
        }
        Reservation reservation = new Reservation(user, resultRoom, LocalDateTime.now(), date, startTime, endDate, endTime, ReservationStatus.PROGRESSING, FixStatus.UNFIXED);
        return Optional.ofNullable(reservationRepository.save(reservation)).orElseThrow(() -> new DuplicatedReservationException("ReservationError::: 예약 실패"));

    }

    private Room getResultRoom(Place place, LocalDate date, LocalDate endDate, RoomType selectedType) {
        Room resultRoom = new Room();
        List<Room> roomList = roomRepository.findRoomByPlaceAndRoomKind(place, selectedType);
        List<Room> findReservation = reservationRepository.findByPlaceAndRoomKindAndStartDateAndEndDate(place, selectedType, date, endDate);
        Set<Room> findReservationSet = new HashSet<>(findReservation);
        if (roomList.size() == findReservationSet.size()) {
            throw new DuplicatedReservationException("ReservationError::: 이미 예약이 있습니다.");
        }
        for (Room room : roomList) {
            if (!findReservationSet.contains(room)) {
                resultRoom = room;
            }
        }
        return resultRoom;
    }

    private Room getResultRoom(Place place, LocalTime startLocalTime, LocalTime endLocalTime, LocalDate date, RoomType selectedType) {
        int startTime = startLocalTime.getHour();
        int endTime = endLocalTime.getHour();

        List<Room> reservedRoomList = roomRepository.findRoomByPlaceIdAndRoomType(place.getId(), selectedType);
        List<Reservation> findReservationList = reservationRepository.findAllByPlaceIdAndRoomTypeAndDate(place.getId(), selectedType, date);
        int maxTime = 24;
        if (place.getPlaceEnd().getHour() > place.getPlaceStart().getHour()) {
            maxTime = place.getPlaceEnd().getHour();
        }
        int maxWindowSize = maxTime - startTime;
        int window = endTime - startTime;
        Map<Integer, ReservedRoom> reservedRoomMap = getReservedRoomMap(place, findReservationList, reservedRoomList, date);
        Long resultRoomId = -1L;
        while (window <= maxWindowSize) {
            for (int i = 0; i < reservedRoomMap.size(); i++) {
                ReservedRoom findReservedRoom = reservedRoomMap.get(i);
                if (startTime == endTime && window == 1) {
                    if (findReservedRoom.getTimeStates().get(startTime) && !findReservedRoom.getTimeStates().get(startTime + 1)) {
                        return roomRepository.findById(findReservedRoom.getRoomId());
                    }
                } else {
                    int pCnt = 0;
                    for (int j = startTime; j < startTime + window; j++) {
                        if (!findReservedRoom.getTimeStates().get(j)) {
                            break;
                        } else {
                            pCnt++;
                            if (pCnt == window && findReservedRoom.getTimeStates().get(j) && !findReservedRoom.getTimeStates().get(j + 1)) {
                                return roomRepository.findById(findReservedRoom.getRoomId());
                            }
                        }
                    }
                }
            }
            window++;
        }
        return roomRepository.findById(resultRoomId);
    }

    /**
     * Room 단위로 모든 예약된 시간을 맵으로 저장 후 반환해주는 메서드 (Key: Order, Value: ReservedRoom)
     */
    private Map<Integer, ReservedRoom> getReservedRoomMap(Place findPlace, List<Reservation> findReservationList, List<Room> reservedRoomList, LocalDate selectedDate) {
        Map<Integer, ReservedRoom> reservedRoomMap = new HashMap<>();
        for (int i = 0; i < reservedRoomList.size(); i++) {
            ReservedRoom reservedRoom = new ReservedRoom(reservedRoomList.get(i).getId(), findPlace.getPlaceStart(), findPlace.getPlaceEnd(), selectedDate);
            reservedRoomMap.put(i, reservedRoom);
        }

        for (int i = 0; i < reservedRoomMap.size(); i++) {
            ReservedRoom reservedRoom = reservedRoomMap.get(i);
            for (Reservation reservation : findReservationList) {
                if (reservedRoom.getRoomId().equals(reservation.getRoom().getId())) {
                    for (int time = reservation.getResStartTime().getHour(); time < reservation.getResEndTime().getHour(); time++) {
                        if (reservedRoom.getTimeState(time) && reservationRequestValidation.isOpenToday(findPlace, TimeFormatter.toLocalTime(String.valueOf(time)))) {
                            reservedRoom.getTimeStates().replace(time, false);
                        }
                    }
                    reservedRoomMap.replace(i, reservedRoom);
                }
            }
        }
        return reservedRoomMap;
    }

    private List<Integer> parsingMapToList(Map<Integer, Boolean> inputTimeMap) {
        List<Integer> resultTimeList = new ArrayList<>();

        for (Map.Entry<Integer, Boolean> entry : inputTimeMap.entrySet()) {
            if (entry.getValue()) {
                resultTimeList.add(entry.getKey());
            }
        }
        return resultTimeList;
    }

    private boolean hasFullReservation(int totalReservationCount, int beforeReservationCount) {
        return totalReservationCount - beforeReservationCount > 0;
    }

    private int countBeforeReservationList(List<Reservation> findReservationList) {
        Set<Long> countRoomIdSet = new HashSet<>();
        for (Reservation reservation : findReservationList) {
            countRoomIdSet.add(reservation.getRoom().getId());
        }
        System.out.println("countRoomIdSet = " + countRoomIdSet);
        return countRoomIdSet.size();
    }
}
