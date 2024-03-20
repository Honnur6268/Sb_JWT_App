package com.security.jwt.service;

import com.security.jwt.model.User;

import java.util.Optional;

public interface IUserService {
   Integer saveUser(User user);

   Optional<User> findByUsername(String username);
}
