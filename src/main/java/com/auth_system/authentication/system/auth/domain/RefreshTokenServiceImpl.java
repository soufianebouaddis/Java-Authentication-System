package com.auth_system.authentication.system.auth.domain;

import com.auth_system.authentication.system.auth.dto.RefreshTokenDTO;
import com.auth_system.authentication.system.auth.mapper.Mapper;
import com.auth_system.authentication.system.util.IRefreshToken;
import com.auth_system.authentication.system.util.RefreshTokenService;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
@Service
@NoArgsConstructor
class RefreshTokenServiceImpl implements RefreshTokenService {
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private Mapper<IRefreshToken, RefreshTokenDTO> refreshTokenMapper;

    RefreshTokenServiceImpl
            (RefreshTokenRepository refreshTokenRepository,
             UserRepository userRepository,
             @Qualifier("RefreshTokenMapper") Mapper<IRefreshToken, RefreshTokenDTO> refreshTokenMapper
            ) {
                this.refreshTokenRepository = refreshTokenRepository;
                this.userRepository = userRepository;
                this.refreshTokenMapper = refreshTokenMapper;
            }

    @Override
    public RefreshTokenDTO createRefreshToken(String username) {
        Optional<RefreshToken> optionalToken = refreshTokenRepository.findRefreshTokenByUsername(username);
        if (optionalToken.isPresent()) {
            RefreshToken existingToken = optionalToken.get();
            if (existingToken.getExpiryDate().isAfter(Instant.now())) {
                existingToken.setExpiryDate(Instant.now().plusMillis(28800000));
                RefreshToken token = refreshTokenRepository.save(existingToken);
                return new RefreshTokenDTO(token.getToken());
            } else {
                refreshTokenRepository.delete(existingToken);
            }
        }
        RefreshToken newRefreshToken = RefreshToken.builder()
                .authuser(userRepository.findByUsername(username))
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(28800000))
                .build();
        RefreshToken refreshToken = refreshTokenRepository.save(newRefreshToken);
        return new RefreshTokenDTO(refreshToken.getToken());


    }

    @Override
    public Optional<RefreshToken> findByToken(String token){
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    public Optional<RefreshToken> verifyExpiration(String token){
        Optional<RefreshToken> token1 = refreshTokenRepository.findByToken(token);
        if(token1.get().getExpiryDate().compareTo(Instant.now())<0){
            refreshTokenRepository.delete(token1.get());
            throw new RuntimeException(token1.get().getToken() + " Refresh token is expired. Please make a new login..!");
        }
        return token1;
    }

    @Override
    public boolean validateRefreshToken(String token) {
        try{
            Optional<RefreshToken> optionalToken = refreshTokenRepository.findByToken(token);
            return optionalToken.isPresent() && optionalToken.get().getExpiryDate().isAfter(Instant.now());
        }catch (RuntimeException ex){
            throw new RuntimeException("Refresh token not valide");
        }

    }
}
