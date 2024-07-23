package com.auth_system.authentication.system.auth.service;

import com.auth_system.authentication.system.auth.dto.LoginRequest;
import com.auth_system.authentication.system.auth.dto.RefreshTokenDTO;
import com.auth_system.authentication.system.auth.dto.UserDto;
import com.auth_system.authentication.system.auth.dto.UserInfo;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;

import java.util.Map;

public interface UserService {
    public UserInfo getUser();
    public Map<String , ResponseCookie> authenticate(LoginRequest authRequestDTO) throws Exception;
    public Authentication authenticateUser(LoginRequest authRequestDTO);
    public ResponseCookie createAccessTokenCookie(String accessToken);
    public ResponseCookie createRefreshTokenCookie(String token);
    public RefreshTokenDTO getTokenOfUserByUsername(String username);
    public UserDto findByUsernameOrEmail(String username, String email) throws Exception;
    public void add(UserDto userDto);
}
