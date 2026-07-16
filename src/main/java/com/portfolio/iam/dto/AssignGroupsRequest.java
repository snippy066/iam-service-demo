package com.portfolio.iam.dto;

import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

public record AssignGroupsRequest(@NotEmpty Set<Long> groupIds) {
}
