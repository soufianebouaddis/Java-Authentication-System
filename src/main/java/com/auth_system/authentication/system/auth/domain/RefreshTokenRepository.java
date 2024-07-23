package com.auth_system.authentication.system.auth.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@Repository
interface RefreshTokenRepository extends JpaRepository<RefreshToken,Integer> {
    Optional<RefreshToken> findByToken(String token);
    @Query("SELECT rf FROM RefreshToken rf WHERE rf.authuser.username = :username")
    Optional<RefreshToken> findRefreshTokenByUsername(@Param("username") String username);
}
