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

    public String generateAccessToken(Authentication authentication) {

        log.info("Generating JWT token"+
                "Token Creation Started for: {}",authentication.getName());

        //func1 helper for getting Roles
        String roles = getRolesOfUser(authentication);
        //func2 helper for getting Permissions
        String permissions = getPermissionsOfUser(roles);

        JwtClaimsSet claimsSet = JwtClaimsSet
                .builder()
                .issuer("Lin")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope",permissions)
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

        if(roles.contains("ROLE_ADMIN")) {
            permissions.addAll(List.of("READ", "WRITE"));
        }

        if(roles.contains("ROLE_MANAGER")) {
            permissions.add("READ");
        }

        if(roles.contains("ROLE_USER")) {
            permissions.add("READ");
        }
    return String.join(" ", permissions);
    }
}
