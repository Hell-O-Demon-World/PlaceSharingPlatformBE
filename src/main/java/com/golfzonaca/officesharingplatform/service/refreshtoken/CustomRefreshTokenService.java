package com.golfzonaca.officesharingplatform.service.refreshtoken;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.golfzonaca.officesharingplatform.auth.token.JwtManager;
import com.golfzonaca.officesharingplatform.domain.RefreshToken;
import com.golfzonaca.officesharingplatform.repository.refreshtoken.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class CustomRefreshTokenService implements RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public RefreshToken create(RefreshToken token) {
        return refreshTokenRepository.save(token);
    }

    @Override
    public boolean existToken(Long userId) {
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findFirstByUserId(userId);
        if (optionalRefreshToken.isEmpty()) {
            return false;
        }
        return true;
    }

    @Override
    public RefreshToken getRefreshToken(Long userId) {
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findFirstByUserId(userId);
        if (optionalRefreshToken.isEmpty()) {
            return new RefreshToken();
        }
        return optionalRefreshToken.get();
    }

    @Override
    public void expire(String encodedJwt) throws JsonProcessingException {
        Long userId = JwtManager.getIdByToken(encodedJwt);
        refreshTokenRepository.deleteByUserId(userId);
    }
}
