package com.golfzonaca.officesharingplatform.service.reservation.dto;

import com.golfzonaca.officesharingplatform.web.reservation.form.DefaultTimeOfDay;
import lombok.Getter;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;
@Getter
public class ReservedRoom {
    private Long roomId;
    private Map<Integer, Boolean> timeStates = getTimeMap();

    public ReservedRoom(Long roomId, LocalTime startLocalTime, LocalTime endLocalTime, LocalDate selectedDate) {
        this.roomId = roomId;
        setStartAndEndTimeMap(startLocalTime, endLocalTime, selectedDate);
    }

    private Map<Integer, Boolean> getTimeMap() {
        Map<Integer, Boolean> timeMap = new HashMap<>();
        for (int time : DefaultTimeOfDay.getTimes()) {
            timeMap.put(time, true);
        }
        return timeMap;
    }

    public boolean getTimeState(int time) {
        return this.timeStates.get(time);
    }
    public void setStartAndEndTimeMap(LocalTime startLocalTime, LocalTime endLocalTime, LocalDate selectedDate) {
        Map<Integer, Boolean> resultMap = this.timeStates;
        LocalDateTime realDateTime = LocalDateTime.now();
        LocalDateTime placeDateTime = LocalDateTime.of(selectedDate, startLocalTime);
        int startTime = startLocalTime.getHour();
        int endTime = endLocalTime.getHour();
        if (endTime - startTime == 0) {
            return;
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
        this.timeStates = resultMap;
    }
}
