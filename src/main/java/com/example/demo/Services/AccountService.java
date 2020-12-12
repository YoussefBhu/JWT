package com.example.demo.Services;

import com.example.demo.Entities.Role;
import com.example.demo.Entities.User;

import java.util.List;

public interface AccountService {
    User addNewUser(User appUser);
    Role addNewRole(Role appRole);
    void addRoleToUser(String username,String roleName);
    User loadUserByUsername(String username);
    List<User> listUsers();
}
