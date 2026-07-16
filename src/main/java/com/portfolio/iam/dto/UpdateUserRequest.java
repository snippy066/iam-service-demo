package com.portfolio.iam.dto;

import jakarta.validation.constraints.Size;

/** Partial update for a user's profile / status (admin). Null fields are ignored. */
public record UpdateUserRequest(
        @Size(max = 255) String fullName,
        Boolean enabled) {
}
