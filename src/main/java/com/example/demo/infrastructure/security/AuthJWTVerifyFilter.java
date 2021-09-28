package com.example.demo.infrastructure.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static com.example.demo.infrastructure.security.Constants.HEADER_STRING;
import static com.example.demo.infrastructure.security.Constants.SECRET;
import static com.example.demo.infrastructure.security.Constants.TOKEN_PREFIX;

public class AuthJWTVerifyFilter extends BasicAuthenticationFilter {

    public AuthJWTVerifyFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    private UsernamePasswordAuthenticationToken retrieveAuthToken(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);

        if (token == null) return null;

        String maybeUser = JWT.require(Algorithm.HMAC512(SECRET.getBytes()))
            .build()
            .verify(token.replace(TOKEN_PREFIX, ""))
            .getSubject();

        if (maybeUser == null) return null;

        return new UsernamePasswordAuthenticationToken(maybeUser, null, new ArrayList<>());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String authHeader = req.getHeader(HEADER_STRING);

        if (authHeader == null || !authHeader.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authToken = retrieveAuthToken(req);

        SecurityContextHolder.getContext().setAuthentication(authToken);
        chain.doFilter(req, res);
    }
}