package com.security.springsecurityjwtoauth2.service;

import com.security.springsecurityjwtoauth2.dto.AuthResponseDTO;
import com.security.springsecurityjwtoauth2.dto.TokenType;
import com.security.springsecurityjwtoauth2.jwtAuth.JwtTokenGenerator;
import com.security.springsecurityjwtoauth2.repo.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 10/07/2024 15:25
 * @Description :
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserInfoRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;

    public AuthResponseDTO getJwtTokensAfterAuthentication(Authentication authentication) {
        try {
            var userInfoEntity = userInfoRepo
                    .findByEmailId(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("[AuthService: userLoginAuth] User: {} not found", authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND");
                    });

            String accessToken = jwtTokenGenerator
                    .generateAccessToken(authentication);

            log.info("[AuthService: userLoginAuth] " +
                            "Access token for User: {}, has been generated"
                    , userInfoEntity.getUserName());

            return AuthResponseDTO
                    .builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .userName(userInfoEntity.getUserName())
                    .tokenType(String.valueOf(TokenType.Bearer))
                    .build();
        } catch (Exception e) {
            log.error("[AuthService: userLoginAuth] Exception while" +
                    "authenticating the User due to: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }
}
