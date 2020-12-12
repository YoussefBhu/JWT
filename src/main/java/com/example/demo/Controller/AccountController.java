package com.example.demo.Controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.example.demo.Entities.Role;
import com.example.demo.Entities.User;
import com.example.demo.Services.AccountService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountController {

    private AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PreAuthorize("hasAuthority('CLIENT')")
    public List<User> appUsers() {
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PreAuthorize("hasAuthority('ADMIN')")
    public User saveUser(@RequestBody User appUser) {
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PreAuthorize("hasAuthority('ADMIN')")
    public Role saveRole(@RequestBody Role appRole) {
        return accountService.addNewRole(appRole);
    }

    @PostMapping("/refreshToken")
    public Map<String, String> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            try {
                String jwtRefreshToken = token.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("MyKeyMyKey");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                String username = decodedJWT.getSubject();
                User appUser = accountService.loadUserByUsername(username);
                String jwtAccessToken = JWT
                        .create()
                        .withSubject(appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 3 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getRoles().stream().map(e -> e.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> accessToken = new HashMap<>();
                accessToken.put("Access_Token", jwtAccessToken);
                accessToken.put("Refresh_Token", jwtRefreshToken);
                return accessToken;
            } catch (TokenExpiredException e) {
                response.setHeader("Error-Message", e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        }
        throw new RuntimeException("Bad Refresh Token");
    }
}

