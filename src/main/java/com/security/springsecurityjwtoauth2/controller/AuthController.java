package com.security.springsecurityjwtoauth2.controller;

import com.security.springsecurityjwtoauth2.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 10/07/2024 15:16
 * @Description :
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(Authentication authentication) {
        return ResponseEntity
                .ok(authService
                        .getJwtTokensAfterAuthentication(authentication));
    }

}
