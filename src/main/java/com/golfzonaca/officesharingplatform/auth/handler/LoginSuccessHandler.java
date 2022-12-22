package com.golfzonaca.officesharingplatform.auth.handler;

import com.golfzonaca.officesharingplatform.auth.filter.servlet.JwtHttpServletProvider;
import com.golfzonaca.officesharingplatform.auth.token.JwtManager;
import com.golfzonaca.officesharingplatform.batch.BatchManager;
import com.golfzonaca.officesharingplatform.domain.RefreshToken;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import com.golfzonaca.officesharingplatform.service.refreshtoken.RefreshTokenService;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@Transactional
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtHttpServletProvider jwtHttpServletProvider;
    private final BatchManager batchManager;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        User findUser = userRepository.findByMailLike(authentication.getPrincipal().toString());
        Jwt accessJwt = JwtManager.createAccessJwt(findUser.getId());
        Jwt refreshJwt = createRefreshJwt(findUser.getId());
        JsonObject json = new JsonObject();
        json.addProperty("accessToken", accessJwt.getEncoded());
        json.addProperty("refreshToken", refreshJwt.getEncoded());

        batchManager.reservationClear(findUser.getId());

        jwtHttpServletProvider.responseJsonObject(response, HttpStatus.ACCEPTED, json);
    }

    private Jwt createRefreshJwt(Long userId) {
        RefreshToken refreshToken = new RefreshToken();
        if (refreshTokenService.existToken(userId)) {
            refreshToken = refreshTokenService.getRefreshToken(userId);
        }
        return getJwt(userId, refreshToken);
    }

    private Jwt getJwt(Long userId, RefreshToken refreshToken) {
        if (refreshToken.getId() != null && JwtManager.validateJwt(refreshToken.getEncodedToken())) {
            Jwt refreshJwt = JwtHelper.decode(refreshToken.getEncodedToken());
            log.info("RefreshToken available ::: using current RefreshToken");
            return refreshJwt;
        } else if (refreshToken.getId() != null && !JwtManager.validateJwt(refreshToken.getEncodedToken())) {
            log.info("RefreshToken expired ::: create new RefreshToken And Save");
        } else {
            log.info("Can't find RefreshToken ::: create new RefreshToken And Save");
            User findUser = userRepository.findById(userId);
            refreshToken.updateUser(findUser);
        }
        Jwt refreshJwt = JwtManager.createRefreshJwt(userId);
        refreshToken.updateToken(refreshJwt.getEncoded());
        refreshTokenService.create(refreshToken);
        return refreshJwt;
    }
}
