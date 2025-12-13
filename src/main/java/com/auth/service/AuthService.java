package com.auth.service;

import com.auth.dto.UserDto;
import com.auth.repositories.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;

    public UserDto register(UserDto userDto){
        return userService.createUser(userDto);
    }

}
