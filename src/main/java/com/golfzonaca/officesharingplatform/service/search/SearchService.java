package com.golfzonaca.officesharingplatform.service.search;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.web.main.dto.request.RequestSearchData;

import java.util.List;

public interface SearchService {
    List<Place> findPlaces(RequestSearchData requestSearchData);

    List<Place> filterPlaces(String day, String startTime, String endTime, String city, String subCity, String typeCategory);
}
