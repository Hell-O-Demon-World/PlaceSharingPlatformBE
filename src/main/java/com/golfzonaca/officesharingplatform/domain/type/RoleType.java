package com.golfzonaca.officesharingplatform.domain.type;

public enum RoleType {
    ROLE_USER("사용자"), ROLE_MANAGER("운영자");
    private final String description;

    RoleType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
