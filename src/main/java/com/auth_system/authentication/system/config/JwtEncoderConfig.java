package com.auth_system.authentication.system.config;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;


public class JwtEncoderConfig{
    private final ResourceLoader resourceLoader;

    public JwtEncoderConfig(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public JwtEncoder jwtEncoder() throws Exception {
        Resource privateKeyResource = resourceLoader.getResource("classpath:rsa-key/private_key.pem");
        Resource publicKeyResource = resourceLoader.getResource("classpath:rsa-key/public_key.pem");

        String privateKeyPEM = readPEMFile(privateKeyResource);
        String publicKeyPEM = readPEMFile(publicKeyResource);

        byte[] privateKeyBytes = decodePEM(privateKeyPEM);
        byte[] publicKeyBytes = decodePEM(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        RSAKey rsaKey = new RSAKey.Builder((java.security.interfaces.RSAPublicKey) publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString()) // Generate a unique key ID
                .build();

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new com.nimbusds.jose.jwk.JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    private String readPEMFile(Resource resource) throws IOException {
        try (InputStreamReader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        }
    }

    private byte[] decodePEM(String pemContent) {
        String encoded = pemContent.replaceAll("\\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .trim();
        return Base64.getDecoder().decode(encoded);
    }
}
