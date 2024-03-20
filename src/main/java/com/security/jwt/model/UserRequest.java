package com.security.jwt.model;

import lombok.Data;

@Data
public class UserRequest {
    private String username;
    private String password;
}
