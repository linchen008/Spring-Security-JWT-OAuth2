package com.security.springsecurityjwtoauth2.controller;

import com.security.springsecurityjwtoauth2.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
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

    /**
     * Authenticates the user and generates JWT tokens.
     * This endpoint handles user authentication requests. Upon successful authentication,
     * it generates both access and refresh JWT tokens for the user. These tokens are then
     * returned in the response body, allowing the user to make authenticated requests.
     *
     * @param authentication The authentication object containing the user's credentials.
     * @param response       The HttpServletResponse to which any additional tokens or cookies can be added.
     * @return A {@link ResponseEntity} containing the JWT tokens if authentication is successful; otherwise, an error response.
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(Authentication authentication,
                                              HttpServletResponse response) {
        return ResponseEntity
                .ok(authService
                        .getJwtTokensAfterAuthentication(authentication, response));
    }

    /**
     * Handles the refresh token request to generate a new access token.
     * This endpoint requires the caller to have the 'SCOPE_REFRESH_TOKEN' authority, ensuring that only requests
     * with a valid refresh token can access this method. The method extracts the refresh token from the
     * 'Authorization' header, validates it, and then generates a new access token if the refresh token is valid.
     *
     * @param authorizationHeader The 'Authorization' header containing the refresh token.
     * @return A {@link ResponseEntity} containing the new access token if the refresh token is valid; otherwise, an error response.
     */
    @PreAuthorize("hasAuthority('SCOPE_REFRESH_TOKEN')")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> getAccessToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return ResponseEntity
                .ok(authService.accessWithRefreshToken(authorizationHeader));
    }

}
