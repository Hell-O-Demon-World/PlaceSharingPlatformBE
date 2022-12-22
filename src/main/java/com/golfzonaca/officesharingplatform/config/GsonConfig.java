package com.golfzonaca.officesharingplatform.config;

import com.google.gson.*;
import org.springframework.boot.autoconfigure.gson.GsonBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.lang.reflect.Type;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Configuration
public class GsonConfig {
    @Bean
    public GsonBuilder gsonBuilder(List<GsonBuilderCustomizer> customizers) {

        GsonBuilder builder = new GsonBuilder();
        customizers.forEach((c) -> c.customize(builder));

        builder.registerTypeHierarchyAdapter(LocalDateTime.class, new JsonSerializer<LocalDateTime>() {

            DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            @Override
            public JsonElement serialize(LocalDateTime src, Type typeOfSrc, JsonSerializationContext context) {
                return new JsonPrimitive(DATE_TIME_FORMATTER.format(src));
            }
        });

        return builder;
    }
}
