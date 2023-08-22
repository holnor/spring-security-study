package com.example.springsecurity6demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CardsController {
    @GetMapping("/myCards")
    public String getAccountDetail(){
        return "Here are the cards details from DB";
    }
}
