package com.auth_system.authentication.system.auth.web;

import com.auth_system.authentication.system.auth.domain.UserDetailService;
import com.auth_system.authentication.system.auth.dto.LoginRequest;
import com.auth_system.authentication.system.auth.dto.UserDto;
import com.auth_system.authentication.system.auth.mapper.Mapper;
import com.auth_system.authentication.system.auth.service.IUserAuth;
import com.auth_system.authentication.system.auth.service.UserService;
import com.auth_system.authentication.system.util.JwtService;
import com.auth_system.authentication.system.util.RefreshTokenService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
@Slf4j
public class AuthController {
    @Value("${cookie.accessCookie}")
    private String COOKIE_NAME ;
    @Value("${cookie.refreshCookie}")
    private String REFRESH_TOKEN;

    private UserService userService;

    private Mapper<IUserAuth,UserDto> userMapper;

    private RefreshTokenService jwtUtils;

    private UserDetailService detailService;

    private PasswordEncoder encoder;

    private JwtService jwtService;

    private AuthenticationManager authenticationManager;

    private SecurityContextLogoutHandler logoutHandler;

    private final Logger logger = LoggerFactory.getLogger(AuthController.class);

    public AuthController(UserService userService, @Qualifier("userMapper") Mapper<IUserAuth, UserDto> userMapper, RefreshTokenService jwtUtils, UserDetailService detailService, PasswordEncoder encoder, JwtService jwtService, AuthenticationManager authenticationManager, SecurityContextLogoutHandler logoutHandler) {
        this.userService = userService;
        this.userMapper = userMapper;
        this.jwtUtils = jwtUtils;
        this.detailService = detailService;
        this.encoder = encoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.logoutHandler = logoutHandler;
    }



    @PostMapping("/login-cookie")
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest authRequestDTO, HttpServletResponse response) {
        logger.info("User Controller Authentication function called");
        try{
            logger.info("Authentication method inside User controller has been called");

            Map<String, ResponseCookie> cookieMap = userService.authenticate(authRequestDTO);
            response.addHeader(HttpHeaders.SET_COOKIE,cookieMap.get(COOKIE_NAME).toString());
            response.addHeader(HttpHeaders.SET_COOKIE,cookieMap.get(REFRESH_TOKEN).toString());
            return ResponseEntity.status(HttpStatus.OK).body("Connected");
        }
        catch (Exception ex){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error during authentication : "+ex.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        logger.info("User Controller Logout function called");
        try{
            logger.info("user logout successfully");
            this.logoutHandler.logout(request, response, authentication);
            return ResponseEntity.status(HttpStatus.OK).body("User Logout Successfully");
        }
        catch (Exception ex){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error during logout");
        }
    }
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserDto dto) throws Exception {
        logger.info("User Controller Register function called");
        try{
            UserDto user = userService.findByUsernameOrEmail(dto.username(), dto.email());
            if(user != null){
                logger.info("USER : "+user.username());
                return ResponseEntity.status(HttpStatus.OK).body("user already registred");
            }
            UserDto newUser = new UserDto(dto.username(),encoder.encode(dto.password()),dto.nom(),dto.prenom(),dto.email());
            userService.add(newUser);
            return ResponseEntity.status(HttpStatus.OK).body(newUser);
        }catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
    @GetMapping("/profile")
    public ResponseEntity<?> userProfile(){
        logger.info("User Controller profile function called");
        try{
            return ResponseEntity.status(HttpStatus.OK).body(userService.getUser());
        }catch (EntityNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Error user not authenticate or not found in our system");
        }catch (Exception ex){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
        }
    }
    @GetMapping("/isAuthenticated")
    public ResponseEntity<?> checkAuthentication(){
        logger.info("User Controller authentication verifiying function called");
        try{
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            return ResponseEntity.status(HttpStatus.OK).body(authentication != null && authentication.isAuthenticated());
        }catch (EntityNotFoundException ex){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error during verify user authentication");
        }
    }
    @GetMapping
    public ResponseEntity<?> greeting(){
        return ResponseEntity.status(HttpStatus.OK).body("Hello world");
    }
}
