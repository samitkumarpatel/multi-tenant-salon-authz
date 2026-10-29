package net.samitkumar.multi_tenant_salon_authz.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import java.util.Locale;

@Configuration
public class AuthI18nConfig {
    @Bean org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService authorizationConsentService() {
        return new org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService();
    }

    @Bean LocaleResolver localeResolver() {
        return new LocaleResolver() {
            @Override public Locale resolveLocale(HttpServletRequest request) { return AuthLanguages.resolve(request); }
            @Override public void setLocale(HttpServletRequest request, HttpServletResponse response, Locale locale) {
                throw new UnsupportedOperationException("Language changes are handled before security filters.");
            }
        };
    }
}
