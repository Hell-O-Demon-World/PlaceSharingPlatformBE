package com.golfzonaca.officesharingplatform.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    public Caffeine caffeineConfig() {
        return Caffeine
                .newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(60, TimeUnit.MINUTES)
                .recordStats();
    }

    @Bean
    public CacheManager cacheManager(Caffeine caffeine) {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(caffeine);
        return cacheManager;
    }

// 상기 : 하나의 설정을 사용
// 하기 : 캐시별로 각각 설정

    /*@Bean
    public CacheManager cacheManager() {
        SimpleCacheManager cacheManager = new SimpleCacheManager();

        List<CaffeineCache> cacheList = Arrays
                .stream(CacheType.values())
                .map(cache -> new CaffeineCache(
                        cache.getName(),
                        Caffeine.newBuilder()
                                .expireAfterWrite(cache.getExpireAfterWrite(), TimeUnit.MINUTES)
                                .refreshAfterWrite(cache.getRefreshAfterWrite(), TimeUnit.MINUTES)
                                .maximumSize(cache.getMaximumSize())
                                .recordStats()
                                .build()
                ))
                .collect(Collectors.toList());
        cacheManager.setCaches(cacheList);
        return cacheManager;
    }*//**/


}
