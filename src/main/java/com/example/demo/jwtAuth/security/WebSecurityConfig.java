package com.example.demo.jwtAuth.security;

import com.example.demo.jwtAuth.CustomEntryPoint;
import com.example.demo.jwtAuth.model.Role;
import com.example.demo.jwtAuth.model.User;
import com.example.demo.jwtAuth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Disable CSRF (cross site request forgery)
        http.csrf().disable();

        // No session will be created or used by spring security
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Entry points
        http.authorizeRequests()
                .and()//
                .exceptionHandling().authenticationEntryPoint(new CustomEntryPoint())
                .and()
                .authorizeRequests()
                .antMatchers("/admin/**").hasAnyRole("ADMIN")//
                .antMatchers("/users/signup").permitAll()
                .antMatchers("/users/login").permitAll()
                .antMatchers("/").permitAll()
                .antMatchers("/hello").hasAnyRole("USER","ADMIN")
                .anyRequest().authenticated();

        // If a user try to access a resource without having enough permissions
//        http.exceptionHandling().accessDeniedPage("/login");

        // Apply JWT
        http.apply(new JwtTokenFilterConfigurer( jwtTokenProvider));

        // Optional, if you want to test the API from a browser
         http.httpBasic();
    }

    @Autowired private UserService userService;

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return authentication -> {
            User user = userService.search(authentication.getName());
            if(user == null){
                return null;
            }
            if(BCrypt.checkpw(authentication.getCredentials().toString(), user.getPassword())){
                return new UsernamePasswordAuthenticationToken(user.getUsername(),
                        user.getPassword(), buildRoles(user.getRoles()));
            }
            return null;
        };
    }

    public static List<GrantedAuthority> buildRoles(List<Role> roles){
        List<GrantedAuthority> authorityList = new ArrayList<>();
        for(Role role : roles)
            authorityList.add((GrantedAuthority) () -> "ROLE_"+role);
        return authorityList;
    }

}