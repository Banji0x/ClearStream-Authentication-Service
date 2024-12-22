package org.clearstream.authentication.models.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.ZonedDateTime;
import java.util.Map;

public record ErrorResponseDto(Integer httpStatus, String errorMessage, Map<String, String> errors,
                               @JsonFormat(shape = JsonFormat.Shape.STRING)
                               ZonedDateTime timeStamp) {
}
