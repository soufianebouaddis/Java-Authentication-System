package com.auth_system.authentication.system.config;

import com.auth_system.authentication.system.auth.web.AuthController;
import com.auth_system.authentication.system.util.JwtService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.*;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class JwtDecoderConfig{
    @Value("classpath:rsa-key/public_key.pem")
    private Resource publicKeyResource;
    private final JwtService util;
    private final Logger logger = LoggerFactory.getLogger(JwtDecoderConfig.class);
    public JwtDecoderConfig(JwtService util) {
        this.util = util;
    }

    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) this.util.loadPublicKey(publicKeyResource);
        final NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
        return decoder;
    }

}
