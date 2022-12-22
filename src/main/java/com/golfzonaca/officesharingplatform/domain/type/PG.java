package com.golfzonaca.officesharingplatform.domain.type;

public enum PG {
    KAKAOPAY("카카오페이"), NICEPAY("나이스페이");
    private final String description;

    PG(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
