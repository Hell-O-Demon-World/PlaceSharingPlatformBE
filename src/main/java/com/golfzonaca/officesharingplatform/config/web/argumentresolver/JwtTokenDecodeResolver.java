package com.golfzonaca.officesharingplatform.config.web.argumentresolver;

import com.golfzonaca.officesharingplatform.annotation.TokenUserId;
import com.golfzonaca.officesharingplatform.auth.token.JwtManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Slf4j
@Component
public class JwtTokenDecodeResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        boolean isTokenUserId = parameter.getParameterAnnotation(TokenUserId.class) != null;
        boolean isLong = Long.class.equals(parameter.getParameterType());
        return isTokenUserId && isLong;
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        String authorizationHeader = webRequest.getHeader("Authorization");
        if (authorizationHeader == null) {
            throw new Exception("Access Token이 존재하지 않습니다.");
        }
        Long userId = JwtManager.getIdByToken(authorizationHeader);
        log.info("Decoded userId is ::: " + userId);
        return userId;
    }
}
