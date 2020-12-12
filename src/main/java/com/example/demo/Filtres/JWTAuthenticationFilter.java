package com.example.demo.Filtres;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.demo.Entities.User;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
            AuthenticationException {
        User user = new User();
        user.setUserName(request.getParameter("username"));
        user.setPassword(request.getParameter("password"));
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUserName(),user.getPassword())
        );
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        org.springframework.security.core.userdetails.User authenticatedUser = (org.springframework.security.core.userdetails.User) authResult.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("MyKeyMyKey");
        String jwtAccessToken= JWT
                .create()
                .withSubject(authenticatedUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+2*60*1000)) // 2 mins
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles",authenticatedUser.getAuthorities().stream().map((a)->a.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm);
        String jwtRefreshToken= JWT
                .create()
                .withSubject(authenticatedUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+10*24*3600*1000)) // 10 jours
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
        Map<String,String> accessToken=new HashMap<>();
        accessToken.put("Access_Token",jwtAccessToken);
        accessToken.put("Refresh_Token",jwtRefreshToken);
        response.setContentType("application/json");
        new JsonMapper().writeValue(response.getOutputStream(),accessToken);
    }
}
