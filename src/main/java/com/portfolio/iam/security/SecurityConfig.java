package com.portfolio.iam.security;

import com.portfolio.iam.repository.RevokedAccessTokenRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Stateless HTTP security. All endpoints require a validated bearer token except
 * the public auth endpoints, actuator health and the OpenAPI/Swagger UI. Method
 * security ({@code @PreAuthorize}) is enabled for fine-grained authorization.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final String[] PUBLIC_PATHS = {
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/actuator/health",
            "/actuator/health/**",
            "/actuator/info",
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/v3/api-docs",
            "/v3/api-docs/**"
    };

    private final JwtService jwtService;
    private final RevokedAccessTokenRepository revokedAccessTokenRepository;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;

    public SecurityConfig(JwtService jwtService,
                          RevokedAccessTokenRepository revokedAccessTokenRepository,
                          RestAuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtService = jwtService;
        this.revokedAccessTokenRepository = revokedAccessTokenRepository;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OncePerRequestFilter jwtFilter = new JwtAuthenticationFilter(jwtService, revokedAccessTokenRepository);
        OncePerRequestFilter tenantFilter = new TenantFilter();

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_PATHS).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(authenticationEntryPoint))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(tenantFilter, JwtAuthenticationFilter.class);

        return http.build();
    }
}
