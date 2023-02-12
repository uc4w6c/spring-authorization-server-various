package com.example.springauthorizationserveropaque;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("hello")
public class HelloController {
  @PreAuthorize("hasAuthority('SCOPE_message.read')")
  @GetMapping
  public String index() {
    return "Hello!";
  }
}
