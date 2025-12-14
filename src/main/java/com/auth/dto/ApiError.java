package com.auth.dto;

import org.springframework.http.HttpStatus;

import java.time.Clock;
import java.time.OffsetDateTime;

public record ApiError(
        HttpStatus status,
        String error,
        String message,
        String path
) {

    public static ApiError of(HttpStatus status, String error, String message, String path){
        return new ApiError(status, error, message, path);
    }
}
