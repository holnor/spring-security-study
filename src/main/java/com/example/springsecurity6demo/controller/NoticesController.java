package com.example.springsecurity6demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoticesController {
    @GetMapping("/notices")
    public String getAccountDetail(){
        return "Here are the notices from DB";
    }
}
