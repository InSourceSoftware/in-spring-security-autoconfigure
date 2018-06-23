package io.insource.springboot.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {
    @GetMapping("/")
    public String doGet() {
        return "OK";
    }

    @PostMapping("/")
    public String doPost(@RequestBody String request) {
        return "OK " + request;
    }
}
