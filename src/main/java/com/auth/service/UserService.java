package com.auth.service;

import com.auth.dto.UserDto;
import com.auth.entities.Provider;
import com.auth.entities.User;
import com.auth.exceptions.ResourceNotFoundException;
import com.auth.repositories.UserRepo;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepo userRepo;
    private final ModelMapper modelMapper;

    @Transactional
    public UserDto createUser(UserDto userDto){
        if(userDto.getEmail()==null || userDto.getEmail().isBlank())
            throw new IllegalArgumentException("Email is required");

        if(userRepo.existsByEmail(userDto.getEmail()))
            throw new IllegalArgumentException("Email alreaby exists");

        User user = modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider()!=null? userDto.getProvider() : Provider.LOCAL);
        //we will set roles here later.......
        User savedUser = userRepo.save(user);

        return modelMapper.map(savedUser, UserDto.class);
    }

    @Transactional
    public Iterable<UserDto> getAllUsers(){
        return userRepo
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user,UserDto.class))
                .toList();
    }

    @Transactional
    public UserDto getUserByEmail(String email){
        User user = userRepo
                .findByEmail(email)
                .orElseThrow(()-> new ResourceNotFoundException("User not found !!"));

        return modelMapper.map(user,UserDto.class);
    }

    @Transactional
    public UserDto getUserById(String id){
        UUID userId = UUID.fromString(id);
        User user = userRepo
                .findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found !!"));
        return modelMapper.map(user, UserDto.class);
    }

    @Transactional
    public void deleteUser(String id){
        UUID userId = UUID.fromString(id);
        User user = userRepo.findById(userId).orElseThrow(()-> new ResourceNotFoundException("User not found !!"));
        userRepo.delete(user);
    }

    @Transactional
    public UserDto updateUser(UserDto userDto, String id){
        UUID userId = UUID.fromString(id);
        User existingUser = userRepo.findById(userId).orElseThrow(()->new RuntimeException("User not found !!"));
        if(userDto.getName()!=null) existingUser.setName(userDto.getName());
        if(userDto.getImage()!=null) existingUser.setImage(userDto.getImage());
        if(userDto.getPassword()!=null) existingUser.setPassword(userDto.getPassword());
        User updatedUser = userRepo.save(existingUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

}
