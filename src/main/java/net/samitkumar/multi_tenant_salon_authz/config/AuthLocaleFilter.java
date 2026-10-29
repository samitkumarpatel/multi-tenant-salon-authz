package net.samitkumar.multi_tenant_salon_authz.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.time.Duration;

/** Run after forwarding/session filters but before Spring Security's login handlers (order -100). */
@Component
@Order(-101)
public class AuthLocaleFilter extends OncePerRequestFilter {
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var previous = LocaleContextHolder.getLocaleContext();
        var locale = AuthLanguages.resolve(request);
        request.setAttribute(AuthLanguages.ATTRIBUTE, locale);
        LocaleContextHolder.setLocale(locale);
        response.setHeader(HttpHeaders.CONTENT_LANGUAGE, locale.toLanguageTag());
        if (AuthLanguages.requested(request).isPresent()) {
            String path = request.getContextPath().isEmpty() ? "/" : request.getContextPath();
            response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(AuthLanguages.COOKIE, locale.getLanguage())
                    .path(path).httpOnly(true).secure(request.isSecure()).sameSite("Lax").maxAge(Duration.ofDays(365)).build().toString());
        }
        try { chain.doFilter(request, response); }
        finally { LocaleContextHolder.setLocaleContext(previous); }
    }
}
