package com.auth_system.authentication.system.auth.service;

public interface IUserAuth {
    int getId();
    String getUsername();
    String getNom();
    String getPrenom();
    String getPassword();
    String getEmail();
}