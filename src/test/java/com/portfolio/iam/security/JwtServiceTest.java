package com.portfolio.iam.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.portfolio.iam.config.AppProperties;
import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.domain.entity.User;
import java.util.Set;
import org.junit.jupiter.api.Test;

class JwtServiceTest {

    private static final String SECRET = "test-secret-that-is-at-least-32-bytes-long!!";

    private JwtService serviceWithTtl(long ttlSeconds) {
        AppProperties props = new AppProperties(
                new AppProperties.Security(
                        new AppProperties.Security.Jwt(SECRET, "iam-service", ttlSeconds, 3600),
                        new AppProperties.Security.Lockout(5)),
                null);
        return new JwtService(props);
    }

    private User sampleUser() {
        User user = User.builder()
                .id(42L)
                .email("alice@example.com")
                .tenantId("primary")
                .build();
        user.getRoles().add(Role.builder().id(1L).name("ROLE_USER").build());
        user.getRoles().add(Role.builder().id(2L).name("ROLE_ADMIN").build());
        return user;
    }

    @Test
    void createAndParse_roundTrips() {
        JwtService service = serviceWithTtl(900);
        String token = service.createAccessToken(sampleUser());

        AuthenticatedUser principal = service.parse(token);

        assertThat(principal.userId()).isEqualTo(42L);
        assertThat(principal.email()).isEqualTo("alice@example.com");
        assertThat(principal.tenantId()).isEqualTo("primary");
        assertThat(principal.jti()).isNotBlank();
        assertThat(principal.roles()).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void parse_rejectsExpiredToken() {
        JwtService service = serviceWithTtl(-10); // already expired
        String token = service.createAccessToken(sampleUser());

        assertThatThrownBy(() -> service.parse(token))
                .isInstanceOf(JWTVerificationException.class);
    }

    @Test
    void parse_rejectsTamperedToken() {
        JwtService service = serviceWithTtl(900);
        String token = service.createAccessToken(sampleUser());
        // Flip a character in the payload segment.
        String tampered = token.substring(0, token.length() - 3) + "abc";

        assertThatThrownBy(() -> service.parse(tampered))
                .isInstanceOf(JWTVerificationException.class);
    }

    @Test
    void parse_rejectsTokenSignedWithDifferentSecret() {
        JwtService issuer = serviceWithTtl(900);
        String token = issuer.createAccessToken(sampleUser());

        AppProperties otherProps = new AppProperties(
                new AppProperties.Security(
                        new AppProperties.Security.Jwt("a-completely-different-secret-32bytes-long!!",
                                "iam-service", 900, 3600),
                        new AppProperties.Security.Lockout(5)),
                null);
        JwtService verifier = new JwtService(otherProps);

        assertThatThrownBy(() -> verifier.parse(token))
                .isInstanceOf(JWTVerificationException.class);
    }

    @Test
    void constructor_rejectsBlankSecret() {
        AppProperties props = new AppProperties(
                new AppProperties.Security(
                        new AppProperties.Security.Jwt("", "iam-service", 900, 3600),
                        new AppProperties.Security.Lockout(5)),
                null);
        assertThatThrownBy(() -> new JwtService(props))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void roles() {
        Set<String> roles = serviceWithTtl(900).parse(serviceWithTtl(900).createAccessToken(sampleUser())).roles();
        assertThat(roles).hasSize(2);
    }
}
