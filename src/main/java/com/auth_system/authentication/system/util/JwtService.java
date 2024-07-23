package com.auth_system.authentication.system.util;

import io.jsonwebtoken.Claims;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public interface JwtService {
    public String extractUsername(String token);

    public Date extractExpiration(String token);
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver);
    public Boolean isTokenExpired(String token);
    public String GenerateToken(String username);
    public Boolean validateToken(String token, UserDetails userDetails);

    public String getCurrentAuthenticatedUsername();
    public PublicKey loadPublicKey(Resource resource)throws Exception;
    public PrivateKey loadPrivateKey(Resource resource) throws Exception;
}
