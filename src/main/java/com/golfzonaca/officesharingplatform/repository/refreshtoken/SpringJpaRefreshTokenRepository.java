package com.golfzonaca.officesharingplatform.repository.refreshtoken;

import com.golfzonaca.officesharingplatform.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

@Transactional
public interface SpringJpaRefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

}
