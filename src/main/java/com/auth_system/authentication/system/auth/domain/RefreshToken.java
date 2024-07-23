package com.auth_system.authentication.system.auth.domain;
import com.auth_system.authentication.system.auth.domain.*;
import com.auth_system.authentication.system.auth.service.IUserAuth;
import com.auth_system.authentication.system.util.IRefreshToken;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "t_refresh_tokens")
@Data
class RefreshToken implements IRefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String token;

    private Instant expiryDate;

    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private UserAuth authuser;
    @Override
    public IUserAuth getUserAuth() {
        return this.authuser;
    }
}
