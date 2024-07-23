package com.auth_system.authentication.system.config;

import com.auth_system.authentication.system.auth.domain.UserDetailService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Configuration
public class SecurityConfig {
    @Value("${cookie.accessCookie}")
    private String COOKIE_NAME;
    @Value("${cookie.refreshCookie}")
    private String COOKIE_REFRESH_TOKEN;
    private JwtFilter jwtFilter;
    private final UserDetailService userDetailsService;

    public SecurityConfig( JwtFilter jwtFilter,UserDetailService userDetailsService) {
        this.userDetailsService = userDetailsService;
        this.jwtFilter= jwtFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .oauth2ResourceServer(authorize -> authorize.jwt(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/v1/auth/register").permitAll())
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/v1/auth/refreshToken").permitAll())
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/v1/auth/login-cookie").permitAll())
                .authorizeHttpRequests(
                        authorize -> authorize.requestMatchers("/swagger-ui/**", "/swagger-ui.html",
                                "/v3/api-docs/**").permitAll())
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout
                        .logoutUrl("/api/v1/auth/logout")
                        .permitAll()
                        .logoutSuccessHandler((req, res, auth) -> {
                            res.setStatus(HttpServletResponse.SC_OK);
                        })
                        .invalidateHttpSession(true)
                        .deleteCookies(
                                COOKIE_REFRESH_TOKEN,
                                "JSESSIONID",
                                COOKIE_NAME
                        ))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()).build();

    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Bean
    AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService);
        return authenticationProvider;
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

