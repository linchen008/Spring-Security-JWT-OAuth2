package com.security.springsecurityjwtoauth2.service;

import com.security.springsecurityjwtoauth2.dto.TokenType;
import com.security.springsecurityjwtoauth2.repo.RefreshTokenRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 11/07/2024 23:10
 * @Description :
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class LogoutHandlerService implements LogoutHandler {

    private final RefreshTokenRepo refreshTokenRepo;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        // Retrieve the Authorization header from the request
        final String authHeader = request.getHeader("Authorization");

        // Check if the Authorization header is present and starts with "Bearer"
        // This is to ensure that the token provided is a Bearer token
        if (!authHeader.startsWith(TokenType.Bearer.name())) {
            return; // If not, exit the method without further processing
        }

        // Extract the refresh token from the Authorization header
        // The token is expected to follow immediately after "Bearer "
        final String refreshToken = authHeader.substring(7);

        // Attempt to find the refresh token in the repository
        var storedRefreshToken = refreshTokenRepo
                .findByRefreshToken(refreshToken)
                .map(token -> {
                    token.setRevoked(true); // Mark the token as revoked
                    refreshTokenRepo.save(token); // Save the updated token back to the repository
                    return token; // Return the revoked token
                })
                .orElse(null); // If the token is not found, return null
    }
}
