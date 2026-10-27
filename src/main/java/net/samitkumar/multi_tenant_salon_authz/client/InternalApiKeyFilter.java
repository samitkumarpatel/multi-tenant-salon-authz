package net.samitkumar.multi_tenant_salon_authz.client;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Guards {@code /internal/clients/**}: only the salon API, holding the shared key, may manage clients. It fails closed
 * (no key configured means nothing gets in) and refuses anything that arrived through the public ingress, which always
 * sets {@code X-Forwarded-Host}, since the API reaches authz directly inside the cluster.
 */
final class InternalApiKeyFilter extends OncePerRequestFilter {
    static final String HEADER = "X-Internal-Api-Key";
    private final byte[] key;
    private final boolean refuseForwarded;

    InternalApiKeyFilter(String key, boolean refuseForwarded) {
        this.key = key == null ? new byte[0] : key.getBytes(StandardCharsets.UTF_8);
        this.refuseForwarded = refuseForwarded;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var supplied = request.getHeader(HEADER);
        boolean keyOk = key.length > 0 && supplied != null
                && MessageDigest.isEqual(key, supplied.getBytes(StandardCharsets.UTF_8));
        boolean viaIngress = refuseForwarded && request.getHeader("X-Forwarded-Host") != null;
        if (!keyOk || viaIngress) {
            response.setStatus(viaIngress ? HttpServletResponse.SC_NOT_FOUND : HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        chain.doFilter(request, response);
    }
}
