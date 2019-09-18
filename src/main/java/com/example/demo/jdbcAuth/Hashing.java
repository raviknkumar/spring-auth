package com.example.demo.jdbcAuth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class Hashing {

    private static BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    public static String hash(String s) {
        return bCryptPasswordEncoder.encode(s);
    }

    public static BCryptPasswordEncoder getEncoder() {
        return bCryptPasswordEncoder;
    }
}