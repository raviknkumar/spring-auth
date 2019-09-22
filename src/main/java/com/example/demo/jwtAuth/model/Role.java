package com.example.demo.jwtAuth.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    ADMIN("ADMIN"),
    USER("USER");

    String roleName;
    Role(String roleName) {
        this.roleName = roleName;
    }

    public String getAuthority() {
        return roleName;
    }

}