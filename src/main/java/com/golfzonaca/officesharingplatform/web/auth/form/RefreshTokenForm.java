package com.golfzonaca.officesharingplatform.web.auth.form;

import lombok.Builder;

@Builder
public class RefreshTokenForm {
    private String accessToken;
    private String refreshToken;
}
