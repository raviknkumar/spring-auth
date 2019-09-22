package com.example.demo.jwtAuth.contoller;

import com.example.demo.jwtAuth.model.User;
import com.example.demo.jwtAuth.model.UserDto;
import com.example.demo.jwtAuth.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/users")
@Slf4j
public class LoginController {

    @Autowired private UserService userService;
    @Autowired private HttpServletRequest request;

    @PostMapping("/login")
    public void handleLogin(@RequestBody UserDto user, HttpServletRequest httpServletRequest, HttpServletResponse response) {
        String jwtToken = userService.signin(user.getUsername(), user.getPassword());
        response.setHeader("Authorization", jwtToken);
        log.info("Entry to: {}", this.getClass().getName());
        log.info("Successfully authenticated. Security context contains: " +
                SecurityContextHolder.getContext().getAuthentication());
    }

    @PostMapping("/signup")
    public String handleSignUp(@RequestBody User user){
        userService.signup(user);
        return "Sign up is successfull";
    }
}
