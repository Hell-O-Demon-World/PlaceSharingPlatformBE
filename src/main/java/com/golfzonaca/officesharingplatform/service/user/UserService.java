package com.golfzonaca.officesharingplatform.service.user;

import com.golfzonaca.officesharingplatform.domain.User;

public interface UserService {

    User findById(Long userId);
}
