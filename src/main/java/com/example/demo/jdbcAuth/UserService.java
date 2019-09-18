package com.example.demo.jdbcAuth;

import com.example.demo.AuthUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.Arrays;
import java.util.HashMap;

@Service
public class UserService implements UserDetailsService {

    private HashMap<String , AuthUser> map = new HashMap<>();

    @PostConstruct
    public void initialize(){

        map.put("a",  AuthUser.builder().userName("a").password("{noop}a")
                .roles(Arrays.asList("USER")).build());
        map.put("b",  AuthUser.builder().userName("b").password("{noop}b")
                .roles(Arrays.asList("USER", "ADMIN"))
                .build());
    }

    private AuthUser getUserByUserName(String userName){
        return map.get(userName);
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        AuthUser user = getUserByUserName(s);
        if (user == null) {
            throw new UsernameNotFoundException(s);
        }
        return new MyUserPrincipal(user);
    }

    public AuthUser getUserByName(String userName){
        AuthUser user = getUserByUserName(userName);
        if (user == null) {
            throw new UsernameNotFoundException(userName);
        }
        return user;
    }


}
