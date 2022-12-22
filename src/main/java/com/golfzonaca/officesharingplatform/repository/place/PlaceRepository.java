package com.golfzonaca.officesharingplatform.repository.place;

import com.golfzonaca.officesharingplatform.domain.Place;
import com.golfzonaca.officesharingplatform.repository.place.dto.FilterData;
import com.golfzonaca.officesharingplatform.web.main.dto.request.RequestSearchData;
import com.querydsl.core.Tuple;

import java.util.List;

public interface PlaceRepository {
    List<Place> findAllPlaces();

    Place findById(long id);

    List<Place> findPlaces(RequestSearchData requestSearchData);

    List<Place> filterPlaces(FilterData filterData);

    String findOpenDayById(Long id);

    Tuple findStartAndEndTimeById(Long id);
}
