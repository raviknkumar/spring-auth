package com.example.demo.jdbcAuth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response, final AccessDeniedException ex) throws IOException, ServletException, IOException {
        log.info("Entry to: {}", this.getClass().getName());
        response.getOutputStream().print("Sorry, You are unauthorized to access thos resource..");
        response.setStatus(403);
        // response.sendRedirect("/my-error-page");
    }

}