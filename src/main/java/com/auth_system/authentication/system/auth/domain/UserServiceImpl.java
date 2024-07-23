package com.auth_system.authentication.system.auth.domain;

import com.auth_system.authentication.system.auth.dto.LoginRequest;
import com.auth_system.authentication.system.auth.dto.RefreshTokenDTO;
import com.auth_system.authentication.system.auth.dto.UserDto;
import com.auth_system.authentication.system.auth.dto.UserInfo;
import com.auth_system.authentication.system.auth.mapper.Mapper;
import com.auth_system.authentication.system.auth.service.IUserAuth;
import com.auth_system.authentication.system.auth.service.UserService;
import com.auth_system.authentication.system.util.IRefreshToken;
import com.auth_system.authentication.system.util.JwtService;
import com.auth_system.authentication.system.util.RefreshTokenService;
import jakarta.persistence.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
class UserServiceImpl implements UserService {
    @Value("${cookie.accessCookie}")
    private String COOKIE_NAME ;
    @Value("${cookie.refreshCookie}")
    private String REFRESH_COOKIE_NAME ;
    //private final Mapper<IRefreshToken,RefreshTokenDTO> refreshTokenMapper;
    private RefreshTokenMapper refreshTokenMapper;
    private final Mapper<IUserAuth,UserDto> userMapper;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    public UserServiceImpl(
            //@Qualifier("RefreshTokenMapper") Mapper<IRefreshToken,RefreshTokenDTO> refreshTokenMapper,
            RefreshTokenMapper refreshTokenMapper,
            UserRepository userRepository,
            @Qualifier("userMapper") Mapper<IUserAuth, UserDto> userMapper,
            JwtService jwtService, RefreshTokenService jwtUtils,
            AuthenticationManager authenticationManager,
            RefreshTokenRepository refreshTokenRepository
    ) {
        this.refreshTokenMapper = refreshTokenMapper;
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.jwtService = jwtService;
        this.jwtUtils = jwtUtils;
        this.authenticationManager = authenticationManager;
        this.refreshTokenRepository = refreshTokenRepository;
    }


    @Override
    public UserInfo getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetail = (UserDetails) authentication.getPrincipal();
        String usernameFromAccessToken = userDetail.getUsername();
        Optional<IUserAuth> user = Optional.ofNullable(userRepository.findByUsername(usernameFromAccessToken));
        UserInfo userinfo = UserInfo.builder().lastName(user.get().getNom())
                .firstName(user.get().getPrenom())
                .username(user.get().getUsername())
                .email(user.get().getEmail()).build();
        if(userinfo != null){
            return userinfo;
        }
        return new UserInfo();
    }
    @Override
    public Map<String , ResponseCookie> authenticate(LoginRequest authRequestDTO) {
            Authentication authentication = authenticateUser(authRequestDTO);
            if (authentication.isAuthenticated()) {
                logger.info("inside if of authenticate in user service impl");
                String accessToken = jwtService.GenerateToken(authRequestDTO.username());
                RefreshTokenDTO refreshToken = jwtUtils.createRefreshToken(authRequestDTO.username());
                ResponseCookie refreshTokenCookie = createRefreshTokenCookie(refreshToken.getToken());
                ResponseCookie accessTokenCookie = createAccessTokenCookie(accessToken);
                logger.info("Refresh and access are created");
                Map<String,ResponseCookie> cookies = new HashMap<>();
                cookies.put(COOKIE_NAME,accessTokenCookie);
                cookies.put(REFRESH_COOKIE_NAME,refreshTokenCookie);
                return cookies;
            } else {
                throw new UsernameNotFoundException("Invalid user request");
            }
    }
    @Override
    public Authentication authenticateUser(LoginRequest authRequestDTO) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequestDTO.username(), authRequestDTO.password())
        );
    }
    @Override
    public ResponseCookie createAccessTokenCookie(String accessToken) {
        return ResponseCookie.from(COOKIE_NAME,
                        accessToken)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(7200) // Max age of cookie -> 2H
                .build();
    }
    @Override
    public ResponseCookie createRefreshTokenCookie(String token) {
        return ResponseCookie.from(REFRESH_COOKIE_NAME,
                        token)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(86400) // max age of cookie (refresh) -> 1Day
                .build();
    }
    @Override
    public RefreshTokenDTO getTokenOfUserByUsername(String username) {
        return refreshTokenMapper.EntityToDto(refreshTokenRepository.findRefreshTokenByUsername(username).orElseThrow(
                ()-> new EntityNotFoundException("User not found")
        ));
    }

    @Override
    public UserDto findByUsernameOrEmail(String username, String email) throws Exception {
        IUserAuth auth = userRepository.findByUsernameOrEmail(username,email);
        if(auth != null){
            return new UserDto(auth.getUsername(), auth.getPassword(), auth.getNom(),auth.getPrenom(), auth.getEmail());
        }
        return null;
    }

    @Override
    public void add(UserDto userDto) {
        UserAuth userAuth = UserAuth.builder()
                .nom(userDto.nom())
                .prenom(userDto.prenom())
                .email(userDto.email())
                .password(userDto.password())
                .username(userDto.username()).build();
        userRepository.save(userAuth);
    }

}
