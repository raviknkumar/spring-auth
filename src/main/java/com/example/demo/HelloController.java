package com.example.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/a")
public class HelloController {

    @GetMapping("/")
    public String greet(){
        return new String("main");
    }

    @GetMapping("/hello")
    public String greetAll(){
        return new String("hello");
    }

//    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/admin")
    public String greetAdmin(){
        return new String("admin");
    }

}
