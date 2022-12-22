package com.golfzonaca.officesharingplatform.config;

import com.golfzonaca.officesharingplatform.service.auth.PrincipalDetailsService;
import com.golfzonaca.officesharingplatform.auth.filter.JsonIdPwAuthenticationProcessingFilter;
import com.golfzonaca.officesharingplatform.auth.filter.JwtAuthenticationFilter;
import com.golfzonaca.officesharingplatform.auth.filter.exception.JwtAuthenticationEntryPoint;
import com.golfzonaca.officesharingplatform.auth.handler.LoginSuccessHandler;
import com.golfzonaca.officesharingplatform.auth.handler.LoginFailureHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
    private final PrincipalDetailsService principalDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private static final RequestMatcher LOGIN_REQUEST_MATCHER = new AntPathRequestMatcher("/auth/signin", "POST");

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JsonIdPwAuthenticationProcessingFilter jsonIdPwAuthenticationProcessingFilter() throws Exception {
        JsonIdPwAuthenticationProcessingFilter jsonAuthenticationFilter = new JsonIdPwAuthenticationProcessingFilter(LOGIN_REQUEST_MATCHER);
        jsonAuthenticationFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        jsonAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler);
        jsonAuthenticationFilter.setAuthenticationFailureHandler(loginFailureHandler);
        return jsonAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/mypage/**", "/auth/refresh").hasRole("USER")
                .and()
                .addFilterAt(jsonIdPwAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, JsonIdPwAuthenticationProcessingFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint);

        http.userDetailsService(principalDetailsService);

        return http.build();
    }

}
