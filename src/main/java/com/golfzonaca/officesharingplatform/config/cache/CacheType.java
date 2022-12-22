package com.golfzonaca.officesharingplatform.config.cache;

public enum CacheType {
    PLACES("places"),
    ROOMS("rooms"),
    RESERVATIONS("reservations");

    private String name;
    private int expireAfterWrite;
    private int refreshAfterWrite;
    private int maximumSize;

    CacheType(String name) {
        this.name = name;
        this.expireAfterWrite = ConstConfig.DEFAULT_EAW_MIN;
        this.refreshAfterWrite = ConstConfig.DEFAULT_RAW_MIN;
        this.maximumSize = ConstConfig.DEFAULT_MAX_SIZE;
    }

    static class ConstConfig {
        static final int DEFAULT_EAW_MIN = 120;
        static final int DEFAULT_RAW_MIN = 60;
        static final int DEFAULT_MAX_SIZE = 10000;
    }
}
