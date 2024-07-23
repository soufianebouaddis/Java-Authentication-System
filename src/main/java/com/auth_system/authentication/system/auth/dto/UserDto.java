package com.auth_system.authentication.system.auth.dto;

public record UserDto(
        String username,
    String password,
    String nom,
    String prenom,
    String email
) {
    public UserDto(String username, String password, String nom, String prenom, String email) {
        this.username = username;
        this.password = password;
        this.nom = nom;
        this.prenom = prenom;
        this.email = email;
    }
}
