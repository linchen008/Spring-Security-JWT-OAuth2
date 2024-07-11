package com.security.springsecurityjwtoauth2.config;


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.springsecurityjwtoauth2.jwtAuth.JwtAccessTokenFilter;
import com.security.springsecurityjwtoauth2.jwtAuth.JwtRefreshTokenFilter;
import com.security.springsecurityjwtoauth2.jwtAuth.JwtTokenUtils;
import com.security.springsecurityjwtoauth2.repo.RefreshTokenRepo;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 09/07/2024 16:32
 * @Description :
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity

@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final UserInfoManagerConfig userInfoManagerConfig;
    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepo refreshTokenRepo;

    @Order(1)
    @Bean
    public SecurityFilterChain loginFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/login/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .userDetailsService(userInfoManagerConfig)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint((request, response, authException) ->
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // to secure the api
                .securityMatcher(new AntPathRequestMatcher("/api/**"))
                // to disable the csrf
                .csrf(AbstractHttpConfigurer::disable)
                // to authorize the request
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // to validate the jwt token
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                // to set the session management to stateless
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // to add the filter before UsernamePasswordAuthenticationFilter to validate the jwt token
                // and set the authentication object in the SecurityContext if the token is valid
                // and not expired and not tampered with the signature.
                .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
                // to handle the exception
                .exceptionHandling(ex -> {
                    log.error("[securityConfig: apiSecurityFilterChain] exception due to : {}", ex);
                    // to handle the exception if the token is not valid or expired or tampered with the signature or not present in the request.
                    ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                    // to handle the exception if the user is not authorized to access the resource.
                    ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /**
     * Configures the security filter chain specifically for refresh token requests.
     * This method sets up security configurations to handle requests to the "/refresh-token/**" endpoint,
     * ensuring that only authenticated requests are processed for token refresh operations.
     *
     * The security configuration includes:
     * - Matching requests to "/refresh-token/**" for this filter chain.
     * - Disabling CSRF protection as it's not needed for stateless JWT authentication.
     * - Requiring all requests to this endpoint to be authenticated, ensuring that only valid, authenticated
     *   requests can attempt to refresh a token.
     * - Configuring OAuth2 resource server with JWT to validate the refresh token.
     * - Setting the session management strategy to stateless to prevent Spring Security from creating
     *   HttpSession instances, aligning with the stateless nature of JWT.
     * - Handling exceptions with custom entry points for authentication and access denied scenarios,
     *   providing meaningful error responses to the client.
     *
     * @param httpSecurity the {@link HttpSecurity} to configure
     * @return the configured {@link SecurityFilterChain} for refresh token requests
     * @throws Exception if an error occurs during the configuration
     */
    @Order(3)
    @Bean
    public SecurityFilterChain refreshTokenSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/refresh-token/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // to validate the jwt token and set the authentication object in the SecurityContext if the token is valid
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // to add the filter before UsernamePasswordAuthenticationFilter to validate the jwt token
                /*
                This operation is performed by the .addFilterBefore() method, which takes two arguments.
                The first argument is an instance of the JwtRefreshTokenFilter class, initialized with rsaKeyRecord, jwtTokenUtils, and refreshTokenRepo.
                These dependencies are essential for the filter to function:
                    1. rsaKeyRecord provides the RSA keys necessary for verifying and signing JWTs.
                    2. jwtTokenUtils contains utility methods for working with JWTs, such as validating their integrity and extracting user information.
                    3. refreshTokenRepo is a repository interface for accessing refresh token data stored in a database, allowing the filter to verify the existence and validity of refresh tokens.
                The second argument, UsernamePasswordAuthenticationFilter.class, specifies that the JwtRefreshTokenFilter should be added before the UsernamePasswordAuthenticationFilter in the security filter chain.
                This ordering is significant because it ensures that the refresh token is processed and, if valid, a new access token is issued before any authentication logic that relies on username and password credentials is executed.
                 */
                .addFilterBefore(new JwtRefreshTokenFilter(rsaKeyRecord,jwtTokenUtils,refreshTokenRepo), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex->{
                    log.info("[SecuirtyConfig: refreshTokenSecuityFilterChain] Exception due to: {}]",ex);
                    ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                    ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    // to secure the h2 console
    @Order(4)
    @Bean
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/h2-console/**"))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                // to display the h2 console in Iframe
                .headers(headers -> headers.frameOptions(Customizer.withDefaults()).disable())
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
                .withPublicKey(rsaKeyRecord.rsaPublicKey())
                .build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey
                .Builder(rsaKeyRecord.rsaPublicKey())
                .privateKey(rsaKeyRecord.rsaPrivateKey())
                .build();

        JWKSource<SecurityContext> jwkSource =
                new ImmutableJWKSet<>(new JWKSet(jwk));

        return new NimbusJwtEncoder(jwkSource);
    }
}
