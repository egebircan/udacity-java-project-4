package com.example.demo.infrastructure.security;

import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static java.util.Collections.emptyList;

@Service
public class DefaultUserDetailsService implements UserDetailsService {
    private final UserRepository applicationUserRepository;

    public DefaultUserDetailsService(UserRepository applicationUserRepository) {
        this.applicationUserRepository = applicationUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User maybeUser = applicationUserRepository.findByUsername(userName);
        if (maybeUser == null) {
            throw new UsernameNotFoundException(userName);
        }
        return new org.springframework.security.core.userdetails.User(maybeUser.getUsername(), maybeUser.getPassword(), emptyList());
    }
}