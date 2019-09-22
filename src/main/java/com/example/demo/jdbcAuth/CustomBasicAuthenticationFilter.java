package com.example.demo.jdbcAuth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

/**
 * This Custom class is used for Filtering and authenticating the incoming request.
 * Authenticated User Object will be cached in In memory Cache
 */
public class CustomBasicAuthenticationFilter extends BasicAuthenticationFilter {

    private UserRepo userRepo;

    public CustomBasicAuthenticationFilter(AuthenticationManager authenticationManager,
                                           UserRepo userRepo) {
        super(authenticationManager);
        this.userRepo = userRepo;

    }

    public CustomBasicAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint) {
        super(authenticationManager, authenticationEntryPoint);
    }

    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
        super.onSuccessfulAuthentication(request, response, authResult);
    }

    /**
     * @param req
     * @param res
     * @param chain Responsible for putting User object in Cache
     */
    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {

        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication securityContextAuthentication = securityContext.getAuthentication();
        if(securityContextAuthentication!=null && securityContextAuthentication.isAuthenticated()){
            chain.doFilter(req, res);
            return;
        }

        String name = req.getHeader("userName");
        String password = req.getHeader("password");
        boolean isValid = true;
        if (name == null || name.equals("") || password == null || password.equals(""))
            isValid = false;

        // Finding User Data in Cache
        User authUser = null;

        String encodedPassword = null;
        User user = new User(name, password);

        // calling Asgard for Authentication
        try {
            authUser = userRepo.findByName(user.getName()).orElse(null);
            if (authUser == null) {
                isValid = false;
                throw new Exception("unauthorized");
            }
            else {
                if ( BCrypt.checkpw(password, authUser.getPassword())){
                    isValid = true;
                }
                else
                    isValid = false;
            }
        } catch (Exception e) {
            isValid = false;
        }

        // Setting the AuthUser object in Request Attribute for Controller Layer usage
        if (isValid) {
            req.setAttribute("authuser", authUser);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authUser, null, getRoles(authUser.getRoles().split(",")));
            securityContext.setAuthentication(authentication);
            HttpSession session = req.getSession(true);
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, securityContext);
            chain.doFilter(req, res);

        } else {
            req.setAttribute("authuser", authUser);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authUser, null);
            securityContext.setAuthentication(authentication);
            chain.doFilter(req, res);
        }
    }

    /**
     * Get roles in form of SimpleGrantedAuthority
     *
     * @param rolesList
     * @return
     */
    private List<SimpleGrantedAuthority> getRoles(String[] rolesList) {
        List<SimpleGrantedAuthority> simpleGrantedAuthorityList = new ArrayList<>();
        for (String role : rolesList) {
            simpleGrantedAuthorityList.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        return simpleGrantedAuthorityList;
    }

    public String convertObjectToJson(Object object) throws JsonProcessingException {
        if (object == null) {
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(object);
    }
}
