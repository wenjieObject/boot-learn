package com.wenjie.esblog.controller;

import com.wenjie.esblog.pojo.User;
import com.wenjie.esblog.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("user")
public class UserController {

    @Autowired
    private UserService userService;


    @PostMapping("/addUser")
    public String addUser(@RequestBody @Valid User user) {

         userService.saveUser(user);
         return "success";
    }

    @GetMapping("/getUser")
    public User getUser() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUsername("12345678");
        user.setPassword("12345678");
        user.setSalt("123@qq.com");

        //throw new APIException("123123");
        return  user;
        //return user;
    }

}
