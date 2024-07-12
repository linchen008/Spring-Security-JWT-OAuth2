package com.security.springsecurityjwtoauth2.service;

import com.security.springsecurityjwtoauth2.dto.AuthResponseDTO;
import com.security.springsecurityjwtoauth2.dto.TokenType;
import com.security.springsecurityjwtoauth2.dto.UserRegistrationDTO;
import com.security.springsecurityjwtoauth2.entity.RefreshTokenEntity;
import com.security.springsecurityjwtoauth2.entity.UserInfoEntity;
import com.security.springsecurityjwtoauth2.jwtAuth.JwtTokenGenerator;
import com.security.springsecurityjwtoauth2.mapper.UserInfoMapper;
import com.security.springsecurityjwtoauth2.repo.RefreshTokenRepo;
import com.security.springsecurityjwtoauth2.repo.UserInfoRepo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Optional;

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
    private final RefreshTokenRepo refreshTokenRepo;
    private final UserInfoMapper userInfoMapper;

    /*
        * This method registers the user in the database and generates the JWT tokens.
        * It first checks if the user already exists in the database. If the user does not exist,
        * it maps the UserRegistrationDTO to UserInfoEntity, saves the user to the database,
        * generates the Access Token and Refresh Token, and saves the Refresh Token to the database.
        * Finally, it creates the Refresh Token Cookie and adds it to the response.
        * The method returns the Access Token and other details in the response body.
     */
    public AuthResponseDTO register(UserRegistrationDTO userRegistrationDTO,
                                    HttpServletResponse httpServletResponse) {
        try {
            log.info("===AUthService: user registration===" +
                    "Registration Process started for user: {}", userRegistrationDTO);

            // Check if the user already exists in the database
            Optional<UserInfoEntity> user = userInfoRepo
                    .findByEmailId(userRegistrationDTO.email());
            // If the user already exists, throw an exception
            if (user.isPresent()) {
                throw new Exception("User Already Exists");
            }
            // Map the UserRegistrationDTO to UserInfoEntity
            UserInfoEntity userInfoEntity = userInfoMapper
                    .convertToEntity(userRegistrationDTO);

            // Save the user to the database
            userInfoRepo.save(userInfoEntity);

            // Create an Authentication object for the user
            Authentication authentication = createAuthenticationObject(userInfoEntity);

            // Generate the Access Token and Refresh Token for the user
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            // Save the Refresh Token to the database
            saveUserRefreshToken(userInfoEntity, refreshToken);

            // Create the Refresh Token Cookie and add it to the response
            createRefreshTokenCookie(httpServletResponse, refreshToken);

            log.info("===AuthService: user registration===" +
                    "User: {} Successfully registered." + userInfoEntity.getUserName());

            return AuthResponseDTO
                    .builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .userName(userInfoEntity.getUserName())
                    .tokenType(TokenType.Bearer.toString())
                    .build();

        } catch (Exception e) {
            log.error("===AuthService: user registration===" +
                    "Exception while registering the user due to: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    // Method to authenticate the user and generate JWT tokens
    public AuthResponseDTO getJwtTokensAfterAuthentication(Authentication authentication,
                                                           HttpServletResponse response) {
        try {
            var userInfoEntity = userInfoRepo
                    .findByEmailId(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("[AuthService: userLoginAuth] " +
                                "User: {} not found", authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND");
                    });

            // Generating the Refresh Token
            String refreshToken = jwtTokenGenerator
                    .generateRefreshToken(authentication);
            // save the refresh token
            saveUserRefreshToken(userInfoEntity, refreshToken);

            // Creating the Cookie for Refresh Token and adding it to the response
            createRefreshTokenCookie(response, refreshToken);

            // Generating the Access Token
            String accessToken = jwtTokenGenerator
                    .generateAccessToken(authentication);

            log.info("[AuthService: userLoginAuth] " +
                            "Access token for User: {}, has been generated"
                    , userInfoEntity.getUserName());
            // Returning the Access Token and Refresh Token
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

    /**
     * Creates and configures a cookie for the refresh token.
     * This method generates a secure, HttpOnly cookie containing the refresh token for the user.
     * The cookie is configured to be secure, meaning it can only be transmitted over HTTPS,
     * and HttpOnly, which prevents it from being accessed through client-side scripts, enhancing security.
     * The cookie's maximum age is set to 15 days, after which it expires and is no longer valid.
     *
     * @param response     The HttpServletResponse to which the cookie will be added.
     * @param refreshToken The refresh token that will be stored in the cookie.
     */
    private void createRefreshTokenCookie(HttpServletResponse response,
                                          String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60); // in seconds
        // Add the cookie to the response
        response.addCookie(refreshTokenCookie);
    }

    private void saveUserRefreshToken(UserInfoEntity userInfoEntity, String refreshToken) {
        var refreshTokenEntity = RefreshTokenEntity
                .builder()
                .user(userInfoEntity)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    public Object accessWithRefreshToken(String authorizationHeader) {
        // Extract the refresh token from the Authorization header
        if (authorizationHeader == null || !authorizationHeader.startsWith(TokenType.Bearer.name())) {
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Invalid Token");
        }
        // Extract the refresh token from the Authorization header by removing the 'Bearer ' prefix
        final String refreshToken = authorizationHeader.substring(7);

        //find refresh token from database and should not be revoked:
        // Same thing can be done through filter.
        var refreshTokenEntity = refreshTokenRepo
                // Find the refresh token in the database
                .findByRefreshToken(refreshToken)
                // Filter out revoked tokens and return the first non-revoked token
                .filter(tokens -> !tokens.isRevoked())
                // If no non-revoked token is found, throw an exception indicating that the refresh token is revoked
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked"));

        // Extract the user information associated with the refresh token
        UserInfoEntity userInfoEntity = refreshTokenEntity.getUser();

        //create Authentication object
        Authentication authentication = createAuthenticationObject(userInfoEntity);

        // Generate a new access token for the user using the refresh token
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        // Return the new access token in the response body
        return AuthResponseDTO
                .builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(userInfoEntity.getUserName())
                .tokenType(TokenType.Bearer.toString())
                .build();
    }

    /**
     * Creates an {@link Authentication} object for a given {@link UserInfoEntity}.
     * This method extracts the user's details such as email (used as username), password, and roles from the {@link UserInfoEntity}.
     * It then converts the comma-separated roles string into an array of {@link GrantedAuthority} objects.
     * These authorities are used to create a {@link UsernamePasswordAuthenticationToken}, which is a specific implementation
     * of {@link Authentication} suitable for user authentication in Spring Security.
     *
     * @param userInfoEntity The user information entity containing the user's email, password, and roles.
     * @return An {@link Authentication} object populated with the user's username, password, and authorities.
     */
    private static Authentication createAuthenticationObject(UserInfoEntity userInfoEntity) {
        // Extract user details from UserDetailsEntity
        String username = userInfoEntity.getEmailId();
        String password = userInfoEntity.getPassword();
        String roles = userInfoEntity.getRoles();

        // Extract authorities from roles (comma-separated)
        String[] roleArray = roles.split(",");

        // Create an array of GrantedAuthority objects from the roles
        GrantedAuthority[] authorities = Arrays
                .stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);
        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }
}
