package com.golfzonaca.officesharingplatform.repository.user;

import com.golfzonaca.officesharingplatform.domain.User;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface SpringDataJpaUserRepository extends JpaRepository<User, Long> {

    User save(User user);

    Optional<User> findById(long id);

    Optional<User> findByEmailLike(String email);

    List<User> findAll();

    @Query("select count(u) from User u where u.email=:email")
    Integer countContainByMail(@Param("email") String email);

    @Query("select count(u) from User u where u.id=:userId")
    Boolean validateUserByUserId(@Param("userId") Long userId);
}
