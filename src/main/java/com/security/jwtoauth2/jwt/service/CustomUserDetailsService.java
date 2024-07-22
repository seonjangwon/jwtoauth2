package com.security.jwtoauth2.jwt.service;

import com.security.jwtoauth2.dto.jwt.CustomUserDetails;
import com.security.jwtoauth2.entity.UserEntity;
import com.security.jwtoauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userData = userRepository.findByUsername(username);

        if (userData != null){
            return new CustomUserDetails(userData);
        }


        return null;
    }
}