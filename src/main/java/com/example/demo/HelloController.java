package com.example.demo;

import com.example.demo.jdbcAuth.Hashing;
import com.example.demo.jdbcAuth.User;
import com.example.demo.jdbcAuth.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;

@RestController
public class HelloController {

    @Autowired private UserRepo userRepo;

    @GetMapping("/")
    public String greet(){
        return new String("main");
    }

    @GetMapping("/hello")
    public String greetAll(){
        return new String("hello");
    }

    @GetMapping("/admin")
    public String greetAdmin(){
        return new String("admin");
    }

    @PostMapping("/signup")
    public User addUser(@RequestBody User user){
        user.setPassword(Hashing.getEncoder().encode(user.getPassword()));
        userRepo.save(user);
        return user;
    }

}

//    @PreAuthorize("hasAnyRole('ADMIN','USER')")
