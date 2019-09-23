package com.example.demo.jwtAuth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

public class CustomEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse res, AuthenticationException e) throws IOException, ServletException {
//        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "you are un authorized");

        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        OutputStream out = res.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(out, "Access Denied");
        out.flush();
    }
}
