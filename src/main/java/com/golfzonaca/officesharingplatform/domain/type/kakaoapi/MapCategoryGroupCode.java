package com.golfzonaca.officesharingplatform.domain.type.kakaoapi;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum MapCategoryGroupCode {

    MARKET("MT1", "대형마트"), CONVENIENCESTORE("CS2", "편의점"), KINDERGARTEN("PS3", "어린이집, 유치원"), SCHOOL("SC4", "학교"), ACADEMY("AC5", "학원"), PARKING("PK6", "주차장"), CHARGINGSTATION("OL7", "주유소, 충전소"), SUBWAYSTATION("SW8", "지하철역"), BANK("BK9", "은행"), CULTURE("CT1", "문화시설"), AGENCY("AG2", "중개업소"), PUBLICINSTITUTION("PO3", "공공기관"), TOURISTATTRACTIONS("AT4", "관광명소"), LODGE("AD5", "숙박"), RESTAURANT("FD6", "음식점"), CAFE("CE7", "카페"), HOSPITAL("HP8", "병원"), PHARMACY("PM9", "약국");

    private String code;
    private String description;


}
