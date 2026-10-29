package net.samitkumar.multi_tenant_salon_authz.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.util.UriComponentsBuilder;
import java.util.*;

/** Shared by MVC pages and security filters, which run before the DispatcherServlet. */
public final class AuthLanguages {
    private AuthLanguages() {}
    public static final String ATTRIBUTE = AuthLanguages.class.getName() + ".locale";
    public static final String COOKIE = "salon-auth-language";
    public record Language(String code, String name) {}
    public static final List<Language> SUPPORTED = List.of(new Language("en", "English"), new Language("da", "Dansk"),
            new Language("sv", "Svenska"), new Language("nb", "Norsk bokmål"), new Language("fr", "Français"), new Language("de", "Deutsch"));

    public static Optional<String> normalize(String value) {
        if (value == null) return Optional.empty();
        String language = value.trim().toLowerCase(Locale.ROOT).split("[-_]", 2)[0];
        if (language.equals("no")) language = "nb";
        final String code = language;
        return SUPPORTED.stream().map(Language::code).filter(code::equals).findFirst();
    }

    public static Optional<String> requested(HttpServletRequest request) {
        var explicit = normalize(request.getParameter("lang"));
        if (explicit.isPresent()) return explicit;
        String uiLocales = request.getParameter("ui_locales");
        if (uiLocales != null) for (String value : uiLocales.split("\\s+")) {
            var candidate = normalize(value); if (candidate.isPresent()) return candidate;
        }
        return Optional.empty();
    }

    public static Locale resolve(HttpServletRequest request) {
        if (request.getAttribute(ATTRIBUTE) instanceof Locale locale) return locale;
        var explicit = requested(request);
        if (explicit.isPresent()) return Locale.forLanguageTag(explicit.get());
        if (request.getCookies() != null) for (var cookie : request.getCookies()) {
            if (COOKIE.equals(cookie.getName())) {
                var saved = normalize(cookie.getValue()); if (saved.isPresent()) return Locale.forLanguageTag(saved.get());
            }
        }
        var locales = request.getLocales();
        while (locales.hasMoreElements()) {
            var language = normalize(locales.nextElement().toLanguageTag());
            if (language.isPresent()) return Locale.forLanguageTag(language.get());
        }
        return Locale.ENGLISH;
    }

    /** English keeps existing default redirect URLs; the preference cookie also survives sign-out. */
    public static String withLanguage(String path, HttpServletRequest request) {
        String language = resolve(request).getLanguage();
        return language.equals("en") ? path : UriComponentsBuilder.fromUriString(path).queryParam("lang", language).build().toUriString();
    }
}
