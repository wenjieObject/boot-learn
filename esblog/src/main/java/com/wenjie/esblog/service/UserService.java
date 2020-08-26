package com.wenjie.esblog.service;

import com.wenjie.esblog.pojo.User;
import com.wenjie.esblog.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;


    public User findUserByName(String username){
        return userRepository.findByUsername(username);
    }

    public void saveUser(User s){
        userRepository.save(s);
    }
}
