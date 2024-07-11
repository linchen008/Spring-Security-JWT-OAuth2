package com.security.springsecurityjwtoauth2.jwtAuth;

import com.security.springsecurityjwtoauth2.config.RSAKeyRecord;
import com.security.springsecurityjwtoauth2.dto.TokenType;
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
 * @createTime : 10/07/2024 22:34
 * @Description :
 */
@RequiredArgsConstructor
@Slf4j
public class JwtAccessTokenFilter extends OncePerRequestFilter {
    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;

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
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try {
            log.info("[JwtAccessTokenFilter: doFilterInternal] :: Strated ");
            log.info("[JwtAccessTokenFilter: doFilterInternal] " +
                    "Filtering the HttpRequest: {}", request.getRequestURI());

            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            // Creates a NimbusJwtDecoder instance using the RSA public key from the RSAKeyRecord instance.
            // The NimbusJwtDecoder is used to decode the JWT token in the Authorization header.
            JwtDecoder jwtDecoder = NimbusJwtDecoder
                    .withPublicKey(rsaKeyRecord.rsaPublicKey())
                    .build();

// Checks if the Authorization header starts with "Bearer".
// This is crucial for determining if the request contains a JWT token in the expected format.
// If the header does not start with "Bearer", the request is passed down the filter chain
// without further processing in this filter, effectively skipping JWT token validation for this request.
            if (!authHeader.startsWith(TokenType.Bearer.name())) {
                filterChain.doFilter(request, response);
            }

            // Extracts the JWT token from the Authorization header by skipping the "Bearer " prefix.
            // This operation assumes the Authorization header is properly formatted as "Bearer <token>",
            // where <token> is the actual JWT token to be processed.
            final String token = authHeader.substring(7);
            // Decodes the JWT token using the NimbusJwtDecoder instance.
            final Jwt jwtToken = jwtDecoder.decode(token);

            // Extracts the username from the JWT token using the getUserName() method from the JwtTokenUtils class.
            final String userName = jwtTokenUtils.getUserName(jwtToken);

            // Checks if the username is not empty
            // and if the current SecurityContext does not have an authenticated user.
            if(!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){
                // Retrieves the UserDetails instance for the username extracted from the JWT token.
                UserDetails userDetails = jwtTokenUtils.userDetails(userName);
                // Validates the JWT token using the isTokenValid() method from the JwtTokenUtils class.
                if(jwtTokenUtils.isTokenValid(jwtToken,userDetails)){
                    // Creates a new SecurityContext instance and sets the authenticated user using the UsernamePasswordAuthenticationToken.
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                    // Creates a new UsernamePasswordAuthenticationToken instance with the UserDetails instance,
                    // null credentials, and authorities from the UserDetails instance.
                    UsernamePasswordAuthenticationToken createdToken =
                            new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    // Sets the WebAuthenticationDetails instance for
                    // the created token using the buildDetails() method from the WebAuthenticationDetailsSource class.
                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // Sets the created token in the SecurityContext instance.
                    securityContext.setAuthentication(createdToken);
                    // Sets the SecurityContext in the SecurityContextHolder.
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            log.info("[JwtAccessTokenFilter: doFilterInternal] :: Completed ");
            // Passes the request and response to the next filter in the chain.
            filterChain.doFilter(request, response);
        } catch (JwtValidationException jwtValidationException) {
            // Logs the exception and throws a ResponseStatusException with the status code 401 (Unauthorized).
            log.error("[JwtAccessTokenFilter: doFilterInternal] :: Exception: {}", jwtValidationException.getMessage());
            // Throws a ResponseStatusException with the status code 401 (Unauthorized) and the exception message.
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    jwtValidationException.getMessage());
        }
    }
}
