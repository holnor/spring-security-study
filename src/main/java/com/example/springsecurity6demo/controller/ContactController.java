package com.example.springsecurity6demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {
    @GetMapping("/contact")
    public String getAccountDetail(){
        return "Here are the contacts from DB";
    }
}
