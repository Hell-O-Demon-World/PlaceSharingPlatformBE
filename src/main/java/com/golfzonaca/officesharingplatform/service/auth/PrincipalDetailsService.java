package com.golfzonaca.officesharingplatform.service.auth;

import com.golfzonaca.officesharingplatform.auth.PrincipalDetails;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User findUser = userRepository.findByMailLike(username);
        if (findUser == null) {
            log.info("user not found {}", username);
            throw new UsernameNotFoundException(username);
        }
        Set<GrantedAuthority> role = getRole("ROLE_USER");

        return PrincipalDetails.builder()
                .username(findUser.getEmail())
                .password(findUser.getPassword())
                .authorities(role)
                .build();
    }

    public UserDetails loadUserByUserId(Long userId) throws UsernameNotFoundException {
        User findUser = userRepository.findById(userId);
        Set<GrantedAuthority> role = getRole("ROLE_USER");

        return PrincipalDetails.builder()
                .username(findUser.getEmail())
                .password(findUser.getPassword())
                .authorities(role)
                .build();
    }

    private Set<GrantedAuthority> getRole(String role_user) {
        Set<GrantedAuthority> grantedAuthorityList = new HashSet<>();
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role_user);
        grantedAuthorityList.add(simpleGrantedAuthority);
        return grantedAuthorityList;
    }
}
