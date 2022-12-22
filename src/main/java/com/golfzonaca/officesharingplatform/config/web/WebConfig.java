package com.golfzonaca.officesharingplatform.config.web;

import com.golfzonaca.officesharingplatform.config.web.argumentresolver.JwtTokenDecodeResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@RequiredArgsConstructor
@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final JwtTokenDecodeResolver jwtTokenDecodeResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(jwtTokenDecodeResolver);
    }
}
