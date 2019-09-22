package com.example.demo.jwtAuth.repo;

import com.example.demo.jwtAuth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.transaction.Transactional;

public interface UserRepo extends JpaRepository<User, Integer> {
    boolean existsByUsername(String username);
    User findByUsername(String username);

    @Transactional
    void deleteByUsername(String username);
}
