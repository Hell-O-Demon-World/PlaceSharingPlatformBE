package com.golfzonaca.officesharingplatform.service.reservation;

import com.golfzonaca.officesharingplatform.web.reservation.form.DefaultTimeOfDay;
import lombok.Getter;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;

@Getter
public class TimeStates {
    private Map<Integer, Boolean> timeStates;

    private TimeStates() {
        this.timeStates = getTimeMap();
    }

    private TimeStates(boolean state) {
        if (state) {
            this.timeStates = getTimeMap();
        } else {
            this.timeStates = getFalseTimeMap();
        }
    }

    private TimeStates(Map<Integer, Boolean> item) {
        this.timeStates = getTimeMap();
    }

    public static TimeStates of() {
        return new TimeStates();
    }

    public static TimeStates allFalse() {
        return new TimeStates(false);
    }

    public void replace(Integer key, Boolean value) {
        this.timeStates.replace(key, value);
    }

    public Map<Integer, Boolean> getTimeMap() {
        Map<Integer, Boolean> timeMap = new HashMap<>();
        for (int time : DefaultTimeOfDay.getTimes()) {
            timeMap.put(time, true);
        }
        return timeMap;
    }

    private Map<Integer, Boolean> getFalseTimeMap() {
        Map<Integer, Boolean> timeMap = new HashMap<>();
        for (int time : DefaultTimeOfDay.getTimes()) {
            timeMap.put(time, false);
        }
        return timeMap;
    }


    public Boolean getTimeState(int time) {
        return this.timeStates.get(time);
    }

    public Map<Integer, Boolean> setStartAndEndTimeMap(LocalTime startLocalTime, LocalTime endLocalTime, LocalDate selectedDate) {
        Map<Integer, Boolean> resultMap = getTimeMap();
        LocalDateTime realDateTime = LocalDateTime.now();
        LocalDateTime placeDateTime = LocalDateTime.of(selectedDate, startLocalTime);
        int startTime = startLocalTime.getHour();
        int endTime = endLocalTime.getHour();
        if (endTime - startTime == 0) {
            return resultMap;
        }
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
            if (realDateTime.toLocalDate().equals(placeDateTime.toLocalDate()) && realDateTime.isAfter(placeDateTime)) {
                startTime = realDateTime.plusHours(1).getHour();
            }
            for (int i = DefaultTimeOfDay.getStartTime(); i < startTime; i++) {
                resultMap.replace(i, false);
            }
            for (int j = endTime; j <= DefaultTimeOfDay.getEndTime(); j++) {
                if (j == 0) {
                    j = 24;
                }
                resultMap.replace(j, false);
            }
        }
        return resultMap;
    }

    public void updateStartAndEndDateTime(LocalDateTime startDateTime, LocalDateTime endDateTime) throws IOException {
        LocalDateTime currentDateTime = LocalDateTime.now();
        int startTime = startDateTime.getHour();
        int endTime = endDateTime.getHour();

        if (endTime < startTime) {
            throw new IOException("Wrong Input Value Exception:: End Time is Smaller Than Start Time.");
        } else if (isSameDateAndTime(startDateTime, endDateTime)) {
            this.timeStates = new HashMap<>();
        } else {
            if (isCurrentTimeIsBiggerThanStartTime(startDateTime, currentDateTime)) {
                startTime = currentDateTime.plusHours(1).getHour();
            }
            for (int i = DefaultTimeOfDay.getStartTime(); i < startTime; i++) {
                this.timeStates.replace(i, false);
            }
            for (int j = endTime; j <= DefaultTimeOfDay.getEndTime(); j++) {
                this.timeStates.replace(j, false);
            }
        }
    }

    private static boolean isCurrentTimeIsBiggerThanStartTime(LocalDateTime startDateTime, LocalDateTime realDateTime) {
        return realDateTime.toLocalDate().equals(startDateTime.toLocalDate()) && realDateTime.isAfter(startDateTime);
    }

    private static boolean isSameDateAndTime(LocalDateTime startDateTime, LocalDateTime endDateTime) {
        return startDateTime.toLocalDate().isEqual(endDateTime.toLocalDate()) && startDateTime.getHour() == endDateTime.getHour();
    }

}
