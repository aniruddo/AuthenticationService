package org.example.userauthenticationservice_sept2024.security;

import org.example.userauthenticationservice_sept2024.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.example.userauthenticationservice_sept2024.models.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByEmail(username);
        if(userOptional.isEmpty()){
            throw new UsernameNotFoundException("User with email: " + username + " not found.");
        }
        return new CustomUserDetails(userOptional.get());
    }
}
