package com.auth_system.authentication.system.util;

import com.auth_system.authentication.system.auth.service.IUserAuth;

import java.time.Instant;

public interface IRefreshToken {
    public int getId();
    public String getToken();
    public Instant getExpiryDate();
    public IUserAuth getUserAuth();
}
