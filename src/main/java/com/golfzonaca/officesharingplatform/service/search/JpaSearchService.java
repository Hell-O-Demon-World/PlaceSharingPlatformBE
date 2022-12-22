package com.golfzonaca.officesharingplatform.service.search;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.repository.place.PlaceRepository;
import com.golfzonaca.officesharingplatform.repository.place.dto.FilterData;
import com.golfzonaca.officesharingplatform.web.formatter.TimeFormatter;
import com.golfzonaca.officesharingplatform.web.main.dto.request.RequestSearchData;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.LinkedList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JpaSearchService implements SearchService {

    private final PlaceRepository placeRepository;

    @Override
    public List<Place> findPlaces(RequestSearchData requestSearchData) {
        return placeRepository.findPlaces(requestSearchData);
    }

    @Override
    public List<Place> filterPlaces(String day, String startTime, String endTime, String city, String subCity, String typeCategory) {

        FilterData filterData = new FilterData();
        if (!day.equals("0")) {
            filterData.setDay(TimeFormatter.toDayOfTheWeek(TimeFormatter.toLocalDate(day)));
        }

        if (!startTime.equals("24")) {
            filterData.setStartTime(TimeFormatter.toLocalTime(startTime));
        }

        if (!endTime.equals("0")) {
            filterData.setEndTime(TimeFormatter.toLocalTime(endTime));
        }

        if (!city.equals("0")) {
            if (city.length() == 3 || city.length() == 5) {
                filterData.setCity(city.substring(0, 2));
            } else if (city.length() == 4) {
                filterData.setCity(city.charAt(0) + city.substring(2, 3));
            } else {
                filterData.setCity(city);
            }
        }

        if (!subCity.equals("0")) {
            filterData.setSubCity(subCity);
        }

        if (!typeCategory.equals("0")) {
            List<RoomType> roomTypeList = new LinkedList<>();
            for (RoomType roomType : RoomType.values()) {
                if (roomType.toString().contains(typeCategory.toUpperCase())) {
                    roomTypeList.add(roomType);
                }
            }
            filterData.setRoomTypeList(roomTypeList);
        }


        return placeRepository.filterPlaces(filterData);
    }
}