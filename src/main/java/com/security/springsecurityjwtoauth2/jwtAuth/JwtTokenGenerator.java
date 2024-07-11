package com.security.springsecurityjwtoauth2.jwtAuth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 10/07/2024 20:09
 * @Description :
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtTokenGenerator {

    private final JwtEncoder jwtEncoder;

    /**
     * Generates a JWT access token for the authenticated user.
     * This method creates a JWT access token with a short lifespan (15 minutes), including the user's roles and permissions as claims.
     * The token is intended for authenticating subsequent requests by the user within its validity period.
     *
     * @param authentication The authentication object containing the principal's details, such as the username and authorities.
     * @return The generated JWT access token as a {@link String}.
     */
    public String generateAccessToken(Authentication authentication) {
        log.info("Generating JWT token" +
                "Token Creation Started for: {}", authentication.getName());
        // Helper function to extract roles from the Authentication object
        String roles = getRolesOfUser(authentication);
        // Helper function to determine permissions based on roles
        String permissions = getPermissionsOfUser(roles);

        // Building the JWT claims set with issuer, issued at, expiration, subject, and scope claims
        JwtClaimsSet claimsSet = JwtClaimsSet
                .builder()
                .issuer("Lin")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", permissions)
                .build();

        // Encoding the claims to generate the JWT token
        return jwtEncoder
                .encode(JwtEncoderParameters.from(claimsSet))
                .getTokenValue();
    }

    //generateRefreshToken

    /**
     * Generates a refresh token for the authenticated user.
     * This method creates a JWT refresh token with a longer lifespan, typically used to obtain a new access token once the current access token expires.
     * The refresh token includes a predefined scope indicating its purpose and a subject set to the authenticated user's name.
     *
     * @param authentication The authentication object containing the principal's details, including the username.
     * @return The generated JWT refresh token as a {@link String}.
     */
    public String generateRefreshToken(Authentication authentication) {
        log.info("[JwtTokenGenerator: generateRefreshToken] Token Creation Started for: {}"
                , authentication.getName());

        JwtClaimsSet claimsSet = JwtClaimsSet
                .builder()
                .issuer("lin")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.DAYS))
                .subject(authentication.getName())
                .claim("scope", "REFRESH_TOKEN")
                .build();

        return jwtEncoder
                .encode(JwtEncoderParameters.from(claimsSet))
                .getTokenValue();
    }

    //func1 helper for getting Roles
    private static String getRolesOfUser(Authentication authentication) {
        return authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }

    //func2 helper for getting Permissions
    private static String getPermissionsOfUser(String roles) {
        Set<String> permissions = new HashSet<>();

        if (roles.contains("ROLE_ADMIN")) {
            permissions.addAll(List.of("READ", "WRITE"));
        }

        if (roles.contains("ROLE_MANAGER")) {
            permissions.add("READ");
        }

        if (roles.contains("ROLE_USER")) {
            permissions.add("READ");
        }
        return String.join(" ", permissions);
    }
}
