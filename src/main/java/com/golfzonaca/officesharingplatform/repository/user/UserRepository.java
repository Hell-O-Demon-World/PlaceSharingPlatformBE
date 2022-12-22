package com.golfzonaca.officesharingplatform.repository.user;


import com.golfzonaca.officesharingplatform.domain.User;

import java.util.List;
import java.util.Optional;


public interface UserRepository {
    User save(User user);

    User findById(Long id);

    User findByMailLike(String email);

    Boolean isUniqueTel(String tel);

    Boolean isUniqueEmail(String email);

    List<User> findAll();

    List<User> findAll(UserSearchCond cond);

    void delete(Long userId);

    Boolean isExistName(String name);

    User findByNameAndTelLike(String name, String tel);

    User findByMailAndTel(String email, String tel);
}
