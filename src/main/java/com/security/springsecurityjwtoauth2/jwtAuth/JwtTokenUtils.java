package com.security.springsecurityjwtoauth2.jwtAuth;

import com.security.springsecurityjwtoauth2.config.UserInfoConfig;
import com.security.springsecurityjwtoauth2.repo.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 10/07/2024 22:53
 * @Description :
 */
@Component
@RequiredArgsConstructor
public class JwtTokenUtils {

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails) {
        //call helper func for getting username from JWT
        final String username = getUserName(jwtToken);
        //call helper func for validating weather or not expired
        boolean isTokenExpired = isTokenExpired(jwtToken);
        boolean isTokenUserSameAsDatabase = username.equals(userDetails.getUsername());
        return !isTokenExpired && isTokenUserSameAsDatabase;
    }

    //helper func for getting username from JWT
    public String getUserName(Jwt jwtToken) {
        return jwtToken.getSubject();
    }

    //helper func for validating weather or not expired
    private boolean isTokenExpired(Jwt jwtToken) {
        return Objects
                //check is not null
                .requireNonNull(jwtToken.getExpiresAt())
                //Checks if this instant is before the specified instant.
                .isBefore(Instant.now());
    }
    //dependency injection
    //UserInfoRepo is a JPA repository for UserInfo entity
    //UserInfo entity is a JPA entity for storing user information
    //UserInfoConfig is a UserDetails implementation
    private final UserInfoRepo userInfoRepo;
    //helper func for getting UserDetails
    public UserDetails userDetails(String emailId) {
        return userInfoRepo
                //find user by emailId
                .findByEmailId(emailId)
                //map to UserInfoConfig
                .map(UserInfoConfig::new)
                .orElseThrow(
                        () -> new UsernameNotFoundException("UserEmail: " + emailId + " dose not exist!"));
    }

}
