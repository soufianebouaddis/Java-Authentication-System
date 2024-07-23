package com.auth_system.authentication.system.util;



import com.auth_system.authentication.system.auth.dto.RefreshTokenDTO;

import java.util.Optional;

public interface RefreshTokenService {
    public RefreshTokenDTO createRefreshToken(String username);
    public Optional<?> findByToken(String token);
    public Optional<?> verifyExpiration(String token);
    public boolean validateRefreshToken(String token);
}
