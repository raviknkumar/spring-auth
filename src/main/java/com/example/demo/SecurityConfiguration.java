package com.example.demo;


import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//@EnableWebSecurity
public class SecurityConfiguration {

    public static void main(String[] args) {
        String s = "hello";
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12); // Strength set as 12
        for(int i=0;i<10;i++)
            System.out.println(encoder.encode(s));
    }

}


//    takes default user name password
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
//    }

//    with in memory userName and password
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("a")
//                .password("a")
//                .roles("USER");
//    }

//    @Bean
//    public PasswordEncoder getPasswordEncoder(){
//        return new BCryptPasswordEncoder(){
//            @Override
//            public boolean matches(CharSequence rawPassword, String encodedPassword) {
//                return rawPassword.toString().equals(encodedPassword);
//            }
//        };
//    }

//    String encodingId = "bcrypt";
//    Map<String, PasswordEncoder> encoders = new HashMap<>();
//    encoders.put(encodingId, new BCryptPasswordEncoder());
//            encoders.put("ldap", new org.springframework.security.crypto.password.LdapShaPasswordEncoder());
//            encoders.put("MD4", new org.springframework.security.crypto.password.Md4PasswordEncoder());
//            encoders.put("MD5", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("MD5"));
//            encoders.put("noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance());
//            encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
//            encoders.put("scrypt", new SCryptPasswordEncoder());
//            encoders.put("SHA-1", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-1"));
//            encoders.put("SHA-256", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"));
//            encoders.put("sha256", new org.springframework.security.crypto.password.StandardPasswordEncoder());
//            return new DelegatingPasswordEncoder(encodingId, encoders);

//the Default password encoder used in security is DelegatingPasswordEncoder.class
//Mention the pwd format as {type}password, eg: {noop}a

//with Bcrypt in action, use only encrypted passwords to be stored in db

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .passwordEncoder(passwordEncoder())
//                .withUser("a")
//                .password("$2a$12$HYJmvyf6e3RjGrAGuAqEruyAWiLVlVTsEPQWSGjBpD4Hp1qgAylR.")
//                .roles("USER");
//    }

//    @Override
//    /**
//     * {typeOfEncoding}password
//     */
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .passwordEncoder(passwordEncoder())
//                .withUser("a")
//                .password("{MD4}9803f4a34e8eb14f96adba49064a0c41")
//                .roles("USER");
//    }
//
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return DefaultPasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }


//CUSTOM AUTH
//@Component
//public class CustomAuthenticationProvider implements AuthenticationProvider {
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        String username = authentication.getName();
//        String password = authentication.getCredentials().toString();
//        if ("user".equals(username) && "password".equals(password)) {
//            return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());
//        } else {
//            throw new BadCredentialsException("Authentication failed");
//        }
//    }
//    @Override
//    public boolean supports(Class<?>aClass) {
//        return aClass.equals(UsernamePasswordAuthenticationToken.class);
//    }
//}


//MULTI STEP AUTH
//@Override
//protected void configure(AuthenticationManagerBuilderauth) throws Exception {
//        // Custom authentication provider - Order 1
//        auth.authenticationProvider(customAuthenticationProvider);
//        // Built-in authentication provider - Order 2
//        auth.inMemoryAuthentication()
//        .withUser("admin")
//        .password("{noop}admin@password")
//        //{noop} makes sure that the password encoder doesn't do anything
//        .roles("ADMIN") // Role of the user
//        .and()
//        .withUser("user")
//        .password("{noop}user@password")
//        .credentialsExpired(true)
//        .accountExpired(true)
//        .accountLocked(true)
//        .roles("USER");
//        }