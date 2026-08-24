package net.samitkumar.multi_tenant_salon_authz.salon;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public record SalonUser(String email, List<SalonInfo> salons) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return salons.stream()
                .map(s -> (GrantedAuthority) s::role)
                .toList();
    }

    @Override
    @JsonIgnore
    public @Nullable String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return email;
    }
}
