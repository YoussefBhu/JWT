package com.example.demo;

import com.example.demo.Entities.Role;
import com.example.demo.Entities.User;
import com.example.demo.Services.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class JwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(AccountService accountService) {
        return args -> {
            accountService.addNewRole(new Role(null,"ADMIN"));
            accountService.addNewRole(new Role(null,"CLIENT"));
            accountService.addNewUser(new User(null,"Admin","1234",new ArrayList<>()));
            accountService.addNewUser(new User(null,"Client","1234",new ArrayList<>()));
            accountService.addRoleToUser("Admin","ADMIN");
            accountService.addRoleToUser("Admin","CLIENT");
            accountService.addRoleToUser("Client","CLIENT");
        };
    }
}
