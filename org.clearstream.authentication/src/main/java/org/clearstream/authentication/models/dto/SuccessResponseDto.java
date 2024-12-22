package org.clearstream.authentication.models.dto;

import java.time.LocalDateTime;
import java.time.ZonedDateTime;

public record SuccessResponseDto<T>(Integer httpStatus, String successMessage, T data, ZonedDateTime timeStamp) {
}
