package com.golfzonaca.officesharingplatform.repository.refreshtoken;

import com.golfzonaca.officesharingplatform.domain.RefreshToken;

import java.util.Optional;

public interface RefreshTokenRepository {
    RefreshToken save(RefreshToken refreshToken);

    RefreshToken findByID(Long id);

    Optional<RefreshToken> findFirstById(Long id);

    Boolean isContainByUserId(Long userId);

    void delete(Long id);

    void deleteByUserId(Long userId);

    RefreshToken findByUserId(Long userId);

    Optional<RefreshToken> findFirstByUserId(Long userId);

}
