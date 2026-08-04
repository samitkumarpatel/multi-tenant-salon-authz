package net.samitkumar.multi_tenant_saloon_authz;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

class SaloonUserTest {

    @Test
    void getUsernameReturnsEmail() {
        var user = new SaloonUser("alice@example.com", "owner", "saloon-1", true);
        assertThat(user.getUsername()).isEqualTo("alice@example.com");
    }

    @Test
    void getPasswordReturnsEmptyString() {
        var user = new SaloonUser("alice@example.com", "owner", "saloon-1", true);
        assertThat(user.getPassword()).isEmpty();
    }

    @Test
    void getAuthoritiesContainRole() {
        var user = new SaloonUser("alice@example.com", "owner", "saloon-1", true);
        assertThat(user.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("owner");
    }

    @Test
    void defaultAccountFlagsAreTrue() {
        var user = new SaloonUser("alice@example.com", "owner", "saloon-1", true);
        assertThat(user.isAccountNonExpired()).isTrue();
        assertThat(user.isAccountNonLocked()).isTrue();
        assertThat(user.isCredentialsNonExpired()).isTrue();
        assertThat(user.isEnabled()).isTrue();
    }
}
