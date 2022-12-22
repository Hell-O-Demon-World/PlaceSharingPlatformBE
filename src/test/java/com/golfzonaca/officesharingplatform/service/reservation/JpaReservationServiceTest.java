package com.golfzonaca.officesharingplatform.service.reservation;

import com.golfzonaca.officesharingplatform.domain.*;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.domain.type.dateformat.DateTimeFormat;
import com.golfzonaca.officesharingplatform.web.formatter.TimeFormatter;
import com.golfzonaca.officesharingplatform.web.reservation.dto.request.ResRequestData;
import com.golfzonaca.officesharingplatform.web.reservation.dto.response.ReservationResponseData;
import com.golfzonaca.officesharingplatform.web.reservation.form.DefaultTimeOfDay;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.Month;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

@RequiredArgsConstructor
class JpaReservationServiceTest {

    @Data
    @Builder
    public static class ReservationTest {

        private Long id;
        private Long userId;
        private Long placeId;
        private Long roomId;
        private Long roomKindId;
        private LocalDate resStartDate;
        private LocalTime resStartTime;
        private LocalDate resEndDate;
        private LocalTime resEndTime;
    }

    @Test
    public void getReservationResponseData() {
        //given
        Place findPlace = Place.builder().id(5L)
                .placeStart(TimeFormatter.toLocalTime("8"))
                .placeEnd(TimeFormatter.toLocalTime("18"))
                .company(Company.builder().id(3L).build())
                .build();
        ResRequestData requestData = new ResRequestData("OFFICE20"
                , "2022-12-02", "2023-01-10"
                , "0", "0");

        List<ReservationResponseData> result = new ArrayList<>();
        String selectedRoomType = requestData.getSelectedType();
        String selectedStartDate = requestData.getStartDate();
        String selectedEndDate = requestData.getEndDate();
        int selectedStartTime = Integer.parseInt(requestData.getStartTime());
        int selectedEndTime = Integer.parseInt(requestData.getEndTime());

        //when
        List<Integer> defaultTimeList = new ArrayList<>();
        LocalDate startLocalDate = TimeFormatter.toLocalDate(selectedStartDate);
        LocalDate endLocalDate = TimeFormatter.toLocalDate(selectedEndDate);

        int startYear = startLocalDate.getYear();
        int endYear = endLocalDate.getYear();
        List<Integer> years = getTotalYears(startYear, endYear);
        for (Integer year : years) {
            Month startMonth = startLocalDate.getMonth();
            Month endMonth = endLocalDate.getMonth();
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
                int startDay = startLocalDate.getDayOfMonth();
                int endDay = endLocalDate.getDayOfMonth();
                Calendar cal = Calendar.getInstance();
                if (month.equals(startMonth) && year.equals(startYear)) {
                    cal.set(year, month.getValue() - 1, startDay);
                    endDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
                } else if (month.equals(endMonth) && year.equals(endYear)) {
                    startDay = 1;
                    cal.set(year, month.getValue() - 1, startDay - 1);
                } else {
                    startDay = 1;
                    cal.set(year, month.getValue() - 1, startDay - 1);
                    endDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
                }
                for (int day = startDay; day < endDay + 1; day++) {
                    String date = year + "-" + month.getValue() + "-" + day;
                    boolean state = false;
                    result.add(ReservationResponseData.builder()
                            .date(DateTimeFormat.of(year, month, day, TimeStates.of()))
                            .state(state)
                            .productType(RoomType.valueOf(selectedRoomType))
                            .build());
                }
            }
        }
        for (ReservationResponseData responseData :result) {
            System.out.println("responseData.getDate() = " + responseData.getDate());
            System.out.println("responseData = " + responseData.isState());
        }
    }

//    private boolean existReservationThatDay(Long placeId, String roomType, String date) {
//        Optional<Reservation> optFindReservation = reservationRepository.findByPlaceIdAndRoomTypeAndDate(placeId, roomType, TimeFormatter.toLocalDate(date));
//        return optFindReservation.isPresent();
//    }

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

    private List<Integer> getTotalYears(int startYear, int endYear) {
        List<Integer> result = new ArrayList<>();
        for (int i = startYear; i < endYear + 1; i++) {
            result.add(i);
        }
        return result;
    }

    @Test
    public void getResultRoom() {
        //given
        Place findPlace = Place.builder().id(5L)
                .placeStart(TimeFormatter.toLocalTime("8"))
                .placeEnd(TimeFormatter.toLocalTime("18"))
                .company(Company.builder().id(3L).build())
                .build();
        LocalDate reservationDate = TimeFormatter.toLocalDate("2022-12-10");
        Map<Long, String> reservationFormat = getReservationFormat();
        List<ReservationTest> findReservationList = getReservationTestList2(reservationDate, 49L, reservationFormat);
        System.out.println("findReservationList = " + findReservationList);
        List<Room> reservedRoomList = getReservationRoomList();
        //when
//        "시작시간기준"
        int startTime = 8;
        int endTime = 9;

        LocalTime newStartTime = TimeFormatter.toLocalTime("1");
        System.out.println("newStartTime.getHour() = " + newStartTime.getHour());
        int maxTime = 24;
        if (findPlace.getPlaceEnd().getHour() > findPlace.getPlaceStart().getHour()) {
            maxTime = findPlace.getPlaceEnd().getHour();
        }
        int maxWindowSize = maxTime - startTime;
        int window = endTime - startTime + 1;
        Map<Integer, ReservedRoom> reservedRoomMap = getReservedRoomMap(findPlace, findReservationList, reservedRoomList);
        Long resultRoomId = -1L;
        boolean endFlag = true;

        while (window <= maxWindowSize && endFlag) {
            for (int i = 0; i < reservedRoomMap.size(); i++) {
                ReservedRoom findReservedRoom = reservedRoomMap.get(i);
                if (startTime == 24) {
                    findReservedRoom.timeStates.put(25, false);
                }
                if (startTime == endTime && window == 1) {
                    if (findReservedRoom.timeStates.get(startTime) && !findReservedRoom.timeStates.get(startTime + 1)) {
                        resultRoomId = findReservedRoom.roomId;
                        endFlag = false;
                    }
                } else {
                    int pCnt = 0;
                    for (int j = startTime; j < startTime + window; j++) {
                        if (!findReservedRoom.timeStates.get(j)) {
                            break;
                        } else {
                            pCnt++;
                            if (pCnt == window && findReservedRoom.timeStates.get(j) && !findReservedRoom.timeStates.get(j + 1)) {
                                resultRoomId = findReservedRoom.roomId;
                                endFlag = false;
                            }
                        }
                    }
                }
                if (!endFlag) {
                    break;
                }
            }
            window++;
        }


        if (resultRoomId == -1L) {
            System.out.println(" 예약가능한 시간이 없습니다. ");
            Room room = null;
        }
        System.out.println("findRoomId = " + resultRoomId);
    }

    //        while (window <= (findPlace.getPlaceEnd().getHour() - startTime) && endFlag) {
//        for (int i = 0; i < reservedRoomMap.size(); i++) {
//            ReservedRoom reservedRoom = reservedRoomMap.get(i);
//            int count = 0;
//            for (int j = startTime; j <= findPlace.getPlaceEnd().getHour() - 1; j++) {
//                if (count > window) {
//                    break;
//                }
//                Boolean aBoolean = reservedRoom.timeStates.get(j);
//                Boolean aBoolean1 = reservedRoom.timeStates.get(j + 1);
//                if (reservedRoom.timeStates.get(j) && reservedRoom.timeStates.get(j + 1)) {
//                    count++;
//                } else if (reservedRoom.timeStates.get(j) || !reservedRoom.timeStates.get(j + 1)) {
//                    if (count == window) {
//                        findRoomId = reservedRoom.roomId;
//                        endFlag = false;
//                        break;
//                    }
//                    break;
//                }
//            }/*
//                for (int j = startTime; j < startTime + window; j++) {
//                    if (!reservedRoom.timeStates.get(j)) {
//                        break;
//                    } else if (!reservedRoom.timeStates.get(j) && (window == j - startTime)) {
//                        findRoomId = reservedRoom.roomId;
//                        endFlag = false;
//                        break;
//                    }
//                }*/
//            if (!endFlag) {
//                break;
//            }
//        }
//
//        window++;
//    }
    private static Map<Long, String> getReservationFormat() {
        Map<Long, String> reservationFormat = new HashMap<>();
        reservationFormat.put(49L, "11-12, 14-15, 16-18");
        reservationFormat.put(50L, "13-16, 16-18");
        reservationFormat.put(51L, "8-12");
        reservationFormat.put(52L, "15-18");
        reservationFormat.put(53L, "11-14");
        reservationFormat.put(54L, "9-11");
        reservationFormat.put(55L, "8-10, 12-14");
        reservationFormat.put(56L, "8-10");
        reservationFormat.put(57L, "10-17");
        reservationFormat.put(58L, "9-11, 13-15, 16-17");
        return reservationFormat;
    }

    private List<ReservationTest> getReservationTestList2(LocalDate reservationDate, Long roomId, Map<Long, String> reservationFormat) {
        Long userId = 3L;
        Long placeId = 5L;
        Long roomKindId = 1L;
        List<ReservationTest> resultReservationList = new ArrayList<>();
        Long reservationCnt = 0L;
        for (long rId = roomId; rId < roomId + reservationFormat.size(); rId++) {
            String[] split1 = reservationFormat.get(rId).split(", ");
            for (String hour : split1) {
                String[] split = hour.split("-");
                LocalTime resStartTime = TimeFormatter.toLocalTime(split[0]);
                LocalTime resEndTime = TimeFormatter.toLocalTime(split[1]);
                ReservationTest reservation = ReservationTest.builder()
                        .id(reservationCnt)
                        .userId(userId)
                        .placeId(placeId)
                        .roomId(rId)
                        .roomKindId(roomKindId)
                        .resStartTime(resStartTime)
                        .resEndTime(resEndTime)
                        .resStartDate(reservationDate)
                        .resEndDate(reservationDate)
                        .build();
                resultReservationList.add(reservation);
                reservationCnt++;
            }
        }
        return resultReservationList;
    }

    @Test
    void getReservationTimeListTest() {
        //given
        Place findPlace = Place.builder().id(5L)
                .placeStart(TimeFormatter.toLocalTime("8"))
                .placeEnd(TimeFormatter.toLocalTime("18"))
                .company(Company.builder().id(3L).build())
                .build();
        List<ReservationTest> findReservationList = getReservationTestList();
        List<Room> reservedRoomList = getReservationRoomList();
        int selectedStartTime = 17;
        //when
        Map<Integer, ReservedRoom> reservedRoomMap = getReservedRoomMap(findPlace, findReservationList, reservedRoomList);
        for (int i = 0; i < reservedRoomMap.size(); i++) {
            System.out.println("reservedRoomMap = " + reservedRoomMap.get(i).getTimeMap());
        }
        int plusMaxPointer = selectedStartTime;
        int minusMinPointer = selectedStartTime;
        for (int i = 0; i < reservedRoomMap.size(); i++) {
            ReservedRoom reservedRoom = reservedRoomMap.get(i);
            int plusPointer = selectedStartTime;
            int minusPointer = selectedStartTime;
            if (!(plusMaxPointer == findPlace.getPlaceEnd().getHour())) {
                for (int j = selectedStartTime; j < findPlace.getPlaceEnd().getHour() - 1; j++) {
                    if (reservedRoom.timeStates.get(j) && reservedRoom.timeStates.get(j + 1)) {
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
                    if (reservedRoom.timeStates.get(j) && reservedRoom.timeStates.get(j - 1)) {
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
        for (int i = minusMinPointer; i < plusMaxPointer + 1; i++) {
            result.add(i);
        }
        System.out.println("result = " + result);

    }

    private Map<Integer, ReservedRoom> getReservedRoomMap(Place findPlace, List<ReservationTest> findReservationList, List<Room> reservedRoomList) {
        Map<Integer, ReservedRoom> reservedRoomMap = new HashMap<>();
        for (int i = 0; i < reservedRoomList.size(); i++) {
            ReservedRoom reservedRoom = new ReservedRoom(reservedRoomList.get(i).getId());
            reservedRoomMap.put(i, reservedRoom);
        }

        for (int i = 0; i < reservedRoomMap.size(); i++) {
            ReservedRoom reservedRoom = reservedRoomMap.get(i);
            for (ReservationTest reservationTest : findReservationList) {
                if (reservedRoom.roomId.equals(reservationTest.roomId)) {
                    for (int time = reservationTest.resStartTime.getHour(); time < reservationTest.resEndTime.getHour(); time++) {
                        if (reservedRoom.timeStates.get(time) && isOpenToday(findPlace, time)) {
                            reservedRoom.timeStates.replace(time, false);
                        }
                    }
                    reservedRoom.setStartAndEndTimeMap(findPlace.getPlaceStart(), findPlace.getPlaceEnd());
                    reservedRoomMap.replace(i, reservedRoom);
                }
            }
        }
        return reservedRoomMap;
    }

    private boolean isOpenToday(Place findPlace, Integer time) {

        LocalTime now = TimeFormatter.toLocalTime(Integer.toString(time));
        return now.isAfter(findPlace.getPlaceStart().minusHours(1)) && now.isBefore(findPlace.getPlaceEnd());
    }

    @Test
    void getStartAndEndTimeTest() {
        Room room = Room.builder()
                .id(1L)
                .roomKind(RoomKind.builder().id(1L).build())
                .place(Place.builder().id(5L)
                        .company(Company.builder().id(3L).build())
                        .build())
                .build();
        ReservedRoom reservedRoom = new ReservedRoom(1L);
        ReservedRoom reservedRoom1 = new ReservedRoom(2L);
        reservedRoom.setStartAndEndTimeMap(TimeFormatter.toLocalTime("18"), TimeFormatter.toLocalTime("4"));
        reservedRoom1.setStartAndEndTimeMap(TimeFormatter.toLocalTime("4"), TimeFormatter.toLocalTime("18"));
        Map<Integer, ReservedRoom> reservedRoomMap = new HashMap<>();
        reservedRoomMap.put(1, reservedRoom);
        reservedRoomMap.put(2, reservedRoom1);

        System.out.println("startAndEndTimeMap = " + reservedRoomMap.get(1).timeStates);
        System.out.println("reservedRoomMap.get = " + reservedRoomMap.get(2).timeStates);
    }

    private static List<ReservationTest> getReservationTestList() {
        List<ReservationTest> findReservationList = new ArrayList<>();
        for (long i = 123; i < 142; i++) {
            long roomId;
            LocalTime resStartTime;
            LocalTime resEndTime;
            if (i == 123) {
                roomId = 49L;
                resStartTime = TimeFormatter.toLocalTime("8");
                resEndTime = TimeFormatter.toLocalTime("18");
            } else if (i == 124) {
                roomId = 50L;
                resStartTime = TimeFormatter.toLocalTime("12");
                resEndTime = TimeFormatter.toLocalTime("18");
            } else if (i == 125) {
                roomId = 51L;
                resStartTime = TimeFormatter.toLocalTime("8");
                resEndTime = TimeFormatter.toLocalTime("10");
            } else if (i == 126) {
                roomId = 51L;
                resStartTime = TimeFormatter.toLocalTime("13");
                resEndTime = TimeFormatter.toLocalTime("18");
            } else if (i == 127) {
                roomId = 52L;
                resStartTime = TimeFormatter.toLocalTime("8");
                resEndTime = TimeFormatter.toLocalTime("11");
            } else if (i == 128) {
                roomId = 53L;
                resStartTime = TimeFormatter.toLocalTime("9");
                resEndTime = TimeFormatter.toLocalTime("11");
            } else if (i == 129) {
                roomId = 53L;
                resStartTime = TimeFormatter.toLocalTime("13");
                resEndTime = TimeFormatter.toLocalTime("15");
            } else if (i == 130) {
                roomId = 53L;
                resStartTime = TimeFormatter.toLocalTime("16");
                resEndTime = TimeFormatter.toLocalTime("18");
            } else if (i == 131) {
                roomId = 54L;
                resStartTime = TimeFormatter.toLocalTime("10");
                resEndTime = TimeFormatter.toLocalTime("12");
            } else if (i == 132) {
                roomId = 54L;
                resStartTime = TimeFormatter.toLocalTime("13");
                resEndTime = TimeFormatter.toLocalTime("15");
            } else if (i == 133) {
                roomId = 54L;
                resStartTime = TimeFormatter.toLocalTime("15");
                resEndTime = TimeFormatter.toLocalTime("18");
            } else if (i == 134) {
                roomId = 55L;
                resStartTime = TimeFormatter.toLocalTime("8");
                resEndTime = TimeFormatter.toLocalTime("10");
            } else if (i == 135) {
                roomId = 55L;
                resStartTime = TimeFormatter.toLocalTime("17");
                resEndTime = TimeFormatter.toLocalTime("18");
            } else if (i == 136) {
                roomId = 56L;
                resStartTime = TimeFormatter.toLocalTime("8");
                resEndTime = TimeFormatter.toLocalTime("10");
            } else if (i == 137) {
                roomId = 56L;
                resStartTime = TimeFormatter.toLocalTime("16");
                resEndTime = TimeFormatter.toLocalTime("18");
            } else if (i == 138) {
                roomId = 57L;
                resStartTime = TimeFormatter.toLocalTime("9");
                resEndTime = TimeFormatter.toLocalTime("11");
            } else if (i == 139) {
                roomId = 57L;
                resStartTime = TimeFormatter.toLocalTime("13");
                resEndTime = TimeFormatter.toLocalTime("15");
            } else if (i == 140) {
                roomId = 58L;
                resStartTime = TimeFormatter.toLocalTime("8");
                resEndTime = TimeFormatter.toLocalTime("10");
            } else {
                roomId = 58L;
                resStartTime = TimeFormatter.toLocalTime("14");
                resEndTime = TimeFormatter.toLocalTime("17");
            }

            ReservationTest reservation = ReservationTest.builder()
                    .id(i)
                    .userId(3L)
                    .placeId(5L)
                    .roomId(roomId)
                    .roomKindId(1L)
                    .resStartTime(resStartTime)
                    .resEndTime(resEndTime)
                    .resStartDate(TimeFormatter.toLocalDate("2022-12-02"))
                    .resEndDate(TimeFormatter.toLocalDate("2022-12-02"))
                    .build();
            findReservationList.add(reservation);
        }
        return findReservationList;
    }

    @Test
    void hasFullReservationTest() {
        ResRequestData requestData = new ResRequestData("desk", "2022-12-02", "2022-12-02", "13", "-1");

        //given
        List<Reservation> findReservationList = getFindReservationList();
        List<Room> reservationRoomList = getReservationRoomList();
        int totalReservationCount = reservationRoomList.size();
        int beforeReservationCount = findReservationList.size();

        System.out.println("totalReservationCount = " + totalReservationCount);
        System.out.println("beforeReservationCount = " + beforeReservationCount);
        assertThat(hasFullReservation(totalReservationCount, beforeReservationCount)).isTrue();

    }

    private List<Room> getReservationRoomList() {
        List<Room> findRoomList = new ArrayList<>();
        for (long i = 49; i < 59; i++) {
            Room room = Room.builder()
                    .id(i)
                    .roomKind(RoomKind.builder().id(1L).build())
                    .place(Place.builder().id(5L)
                            .company(Company.builder().id(3L).build())
                            .build())
                    .build();
            findRoomList.add(room);
        }
        return findRoomList;
    }

    private static List<Reservation> getFindReservationList() {
        List<Reservation> findReservationList = new ArrayList<>();
        for (long i = 49; i < 59; i++) {
            if (i == 57) {
                continue;
            }
            Reservation reservation = Reservation.builder()
                    .id(i + 120L)
                    .user(User.builder().id(3L).build())
                    .room(Room.builder()
                            .id(i)
                            .roomKind(RoomKind.builder().id(1L).build())
                            .place(Place.builder().id(5L)
                                    .company(Company.builder().id(3L).build())
                                    .build())
                            .build())
                    .resStartDate(TimeFormatter.toLocalDate("2022-12-02"))
                    .resEndDate(TimeFormatter.toLocalDate("2022-12-02"))
                    .resStartTime(TimeFormatter.toLocalTime("8"))
                    .resEndTime(TimeFormatter.toLocalTime("18"))
                    .build();
            findReservationList.add(reservation);
        }
        return findReservationList;
    }

    private boolean hasFullReservation(int totalReservationCount, int beforeReservationCount) {
        return totalReservationCount - beforeReservationCount > 0;
    }

    private static class ReservedRoom {
        private final Long roomId;
        private Map<Integer, Boolean> timeStates;

        public ReservedRoom(Long roomId) {
            this.roomId = roomId;
            this.timeStates = getTimeMap();
        }

        private Map<Integer, Boolean> getTimeMap() {
            Map<Integer, Boolean> timeMap = new HashMap<>();
            for (int time : DefaultTimeOfDay.getTimes()) {
                timeMap.put(time, true);
            }
            return timeMap;
        }

        private void setStartAndEndTimeMap(LocalTime startLocalTime, LocalTime endLocalTime) {
            Map<Integer, Boolean> resultMap = this.timeStates;
            int startTime = startLocalTime.getHour();
            int endTime = endLocalTime.getHour();

            if (endTime - startTime < 0) {
                int tempTime = endTime;
                endTime = startTime;
                startTime = tempTime;
                for (int i = startTime; i < endTime; i++) {
                    if (i == 0) {
                        i = 24;
                    }
                    resultMap.replace(i, false);
                }
            } else {

                for (int i = DefaultTimeOfDay.getStartTime(); i < startTime; i++) {
                    if (i == 0) {
                        i = 24;
                    }
                    resultMap.replace(i, false);
                }
                for (int j = endTime; j <= DefaultTimeOfDay.getEndTime(); j++) {
                    if (j == 0) {
                        j = 24;
                    }
                    resultMap.replace(j, false);
                }
            }
            this.timeStates = resultMap;
        }
    }
}