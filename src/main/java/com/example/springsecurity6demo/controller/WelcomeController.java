package com.example.springsecurity6demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

    @GetMapping("/welcome")
    public String sayHello(){
        return "Welcome to Spring App With Security!";
    }
}
