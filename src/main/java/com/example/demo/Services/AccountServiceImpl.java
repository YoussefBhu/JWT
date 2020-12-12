package com.example.demo.Services;

import com.example.demo.Entities.Role;
import com.example.demo.Entities.User;
import com.example.demo.Repositories.RoleRepository;
import com.example.demo.Repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;

    public AccountServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User addNewUser(User appUser) {
        String pw = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pw));
        return userRepository.save(appUser);
    }

    @Override
    public Role addNewRole(Role appRole) {
        return roleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        User user = userRepository.findByUserName(username);
        Role role = roleRepository.findByRoleName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User loadUserByUsername(String username) {
        return userRepository.findByUserName(username);
    }

    @Override
    public List<User> listUsers() {
        return userRepository.findAll();
    }
}
