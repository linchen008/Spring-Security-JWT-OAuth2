package com.security.springsecurityjwtoauth2.jwtAuth;

import com.security.springsecurityjwtoauth2.config.RSAKeyRecord;
import com.security.springsecurityjwtoauth2.repo.RefreshTokenRepo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 11/07/2024 19:12
 * @Description :
 */
@RequiredArgsConstructor
@Slf4j
public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepo refreshTokenRepo;

    /**
     * Same contract as for {@code doFilter}, but guaranteed to be
     * just invoked once per request within a single request thread.
     * See {@link #shouldNotFilterAsyncDispatch()} for details.
     * <p>Provides HttpServletRequest and HttpServletResponse arguments instead of the
     * default ServletRequest and ServletResponse ones.
     *
     * @param request
     * @param response
     * @param filterChain
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("[JwtRefreshTokenFilter: doFilterInternal] :: Started");
            log.info("[JwtRefreshTokenFilter: doFilterInternal] Filtering the HttpRequest: {}", request.getRequestURI());

            // Extracting the Authorization Header
            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            // Creating a JwtDecoder object using the RSA public key from the RSAKeyRecord object
            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            // Checking if the Authorization Header starts with "Bearer "
            if(!authHeader.startsWith("Bearer ")){
                filterChain.doFilter(request, response);
                return;
            }
            // Extracting the token from the Authorization Header
            final String token = authHeader.substring(7);
            // Decoding the token using the JwtDecoder object
            final Jwt jwtRefreshToken = jwtDecoder.decode(token);
            // Extracting the username from the decoded token
            final String username = jwtTokenUtils.getUserName(jwtRefreshToken);
            // Checking if the username is not empty and the user is not already authenticated
            if (!username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                var isRefreshTokenValidInDatabase = refreshTokenRepo
                        // Finding the refresh token in the database
                        .findByRefreshToken(jwtRefreshToken.getTokenValue())
                        // Checking if the refresh token is present and is valid
                        .map(refreshTokenEntity -> !refreshTokenEntity.isRevoked())
                        // Returning false if the refresh token is not present or is revoked
                        .orElse(false);
                // Extracting the UserDetails object from the username
                UserDetails userDetails = jwtTokenUtils.userDetails(username);

                /*
                The condition checks two crucial aspects:
                1. whether the JWT token is valid and whether the refresh token exists and is valid in the database.
                2. This ensures that the user is authenticated with a valid token that is recognized and not revoked by the system.
                 */
                if(jwtTokenUtils.isTokenValid(jwtRefreshToken,userDetails) && isRefreshTokenValidInDatabase){
                    // Creating an empty SecurityContext object
                    /*
                    A new SecurityContext is created using SecurityContextHolder.createEmptyContext().
                    This context will hold the authentication details for the current session.
                    An empty context is used as a starting point to add authenticated user information.
                     */
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                    // Creating a UsernamePasswordAuthenticationToken object
                    // 'createdToken' is used to store the authentication information.
                    // used for new authenticated session.
                    // The token is created using the UserDetails object and the authorities from the UserDetails object
                    /*
                    A UsernamePasswordAuthenticationToken is instantiated with the user's details and authorities.
                    This token serves as a proof of authentication, containing the principal (user details),
                        credentials (set to null as they are not needed here), and authorities (roles).
                     */
                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    // Setting the details of the created token
                    /*
                    This includes information from the HTTP request, such as IP address and session ID,
                    which can be important for security audits and logging.
                     */
                    createdToken.setDetails(
                            // Creating a new WebAuthenticationDetailsSource object
                            new WebAuthenticationDetailsSource()
                                    // Building the details using the current request
                                    .buildDetails(request));
                    // Setting the authentication object in the SecurityContext
                    /*
                    The authentication object (createdToken) is set in the SecurityContext using securityContext.setAuthentication(createdToken).
                    This step officially marks the user as authenticated for the current session.
                     */
                    securityContext.setAuthentication(createdToken);
                    // Setting the SecurityContext in the SecurityContextHolder
                    /*
                    Finally, the populated SecurityContext is set in the SecurityContextHolder
                    using SecurityContextHolder.setContext(securityContext).
                    This makes the user's authentication state available throughout the application,
                    allowing for secure access to protected resources.
                     */
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            log.info("[JwtRefreshTOkenFilter: doFilterInternal] Completed");

            filterChain.doFilter(request,response);

        }catch (JwtValidationException jwtValidationException){
            log.error("[JwtRefreshTokenFilter:doFilterInternal] " +
                    "Exception due to: {}",jwtValidationException.getMessage());
            throw new ResponseStatusException(
                    HttpStatus.NOT_ACCEPTABLE,
                    jwtValidationException.getMessage());
        }
    }
}
