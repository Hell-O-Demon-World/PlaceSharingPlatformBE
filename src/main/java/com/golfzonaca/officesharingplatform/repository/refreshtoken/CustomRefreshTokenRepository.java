package com.golfzonaca.officesharingplatform.repository.refreshtoken;

import com.golfzonaca.officesharingplatform.domain.RefreshToken;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional
@RequiredArgsConstructor
public class CustomRefreshTokenRepository implements RefreshTokenRepository{
    private final QueryRefreshTokenRepository queryRefreshTokenRepository;
    private final SpringJpaRefreshTokenRepository jpaRefreshTokenRepository;

    @Override
    public RefreshToken save(RefreshToken refreshToken) {
        return jpaRefreshTokenRepository.save(refreshToken);
    }

    @Override
    public Optional<RefreshToken> findFirstById(Long id) {
        return queryRefreshTokenRepository.findFirstById(id);
    }

    @Override
    public Optional<RefreshToken> findFirstByUserId(Long userId) {
        return queryRefreshTokenRepository.findFirstByUserId(userId);
    }
    public RefreshToken findByID(Long id) {
        return jpaRefreshTokenRepository.findById(id).get();
    }


    @Override
    public Boolean isContainByUserId(Long userId) {
        return queryRefreshTokenRepository.isContainByUserId(userId).isPresent();
    }

    @Override
    public void delete(Long id) {
        jpaRefreshTokenRepository.deleteById(id);
    }

    @Override
    public void deleteByUserId(Long userId) {
        queryRefreshTokenRepository.deleteByUserId(userId);
    }

    @Override
    public RefreshToken findByUserId(Long userId) {
        return queryRefreshTokenRepository.findByUserId(userId);
    }
}
