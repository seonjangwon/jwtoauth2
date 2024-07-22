package com.security.jwtoauth2.service;

import com.security.jwtoauth2.dto.JoinDTO;
import com.security.jwtoauth2.entity.UserEntity;
import com.security.jwtoauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    public void joinProcess(JoinDTO joinDTO){

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
            return;
        }

        UserEntity data = new UserEntity();
        data.setUsername(username);
        data.setPassword(encoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);


    }
}
