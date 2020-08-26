package com.wenjie.esblog.controller;


import com.wenjie.esblog.pojo.User;
import com.wenjie.esblog.repository.UserRepository;
import jdk.nashorn.internal.ir.CallNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/logger")
public class LoggerController {

    @Autowired
    UserRepository userRepository;


    @GetMapping("/getOne")
    public User getUser(){

        User one = userRepository.getOne((long) 1);
        return one;
    }

}
