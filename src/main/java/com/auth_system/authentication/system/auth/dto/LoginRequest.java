package com.auth_system.authentication.system.auth.dto;

public record LoginRequest(
        String username,
        String password
) {
}
