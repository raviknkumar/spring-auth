package com.example.demo.jdbcAuth;

import com.example.demo.AuthUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CustomAuthFilter extends BasicAuthenticationFilter {

    UserService userService;

    public CustomAuthFilter(AuthenticationManager authenticationManager, UserService userService) {
        super(authenticationManager);
        this.userService = userService;
    }

    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
        super.onSuccessfulAuthentication(request, response, authResult);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String name = request.getHeader("userName");
        String password = request.getHeader("password");

        boolean isValid = true;

        if (name == null || name.isEmpty() || password == null || password.isEmpty()) {
            isValid = false;
        }

        String encodedPassword = null;
        AuthUser authUser;

        authUser = userService.getUserByName(name);
        if (authUser == null)
            isValid = false;

        encodedPassword = Hashing.getEncoder().encode(password);
        if (!encodedPassword.equals(authUser.getPassword())) {
            isValid = false;
        }

        if(isValid){
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authUser, null, getRoles(authUser.getRoles()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } else{
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authUser, null);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
    }

    private List<SimpleGrantedAuthority> getRoles(List<String> rolesList) {
        List<SimpleGrantedAuthority> simpleGrantedAuthorityList = new ArrayList<>();
        for(String role : rolesList) {
            simpleGrantedAuthorityList.add(new SimpleGrantedAuthority("ROLE_"+role));
        }
        return simpleGrantedAuthorityList;
    }
}
