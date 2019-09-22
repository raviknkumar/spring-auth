package com.example.demo.jdbcAuth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User, Integer> {

    Optional<User> findByName(String userName);
}
