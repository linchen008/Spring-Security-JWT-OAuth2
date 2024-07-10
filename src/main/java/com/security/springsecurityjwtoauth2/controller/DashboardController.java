package com.security.springsecurityjwtoauth2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 09/07/2024 23:08
 * @Description :
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DashboardController {
    @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN','ROLE_USER')")
    @GetMapping("/welcome")
    public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication) {
        return ResponseEntity.ok("Welcome " + authentication.getName()+", with scope: "+authentication.getAuthorities());
    }

    @PreAuthorize("hasRole('ROLE_MANAGER')")
    @GetMapping("/manager")
    public ResponseEntity<String> getManagerData(Principal principal) {
        return ResponseEntity.ok("Manager:: "+principal.getName());
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Principal principal) {
        return ResponseEntity.ok("Admin:: "+principal.getName() + "has this message: "+ message);
    }
}
