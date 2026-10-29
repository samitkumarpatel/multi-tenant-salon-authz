package net.samitkumar.multi_tenant_salon_authz;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.Cookie;
import net.samitkumar.multi_tenant_salon_authz.config.AuthLanguages;
import net.samitkumar.multi_tenant_salon_authz.config.AuthLocaleFilter;
import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class AuthI18nIntegrationTest {
    @Autowired WebApplicationContext context;
    @Autowired MessageSource messages;
    @MockitoBean(name="inMemorySalonUserClient") SalonUserClient users;
    @MockitoBean(name="inMemoryNotificationService") NotificationService notifications;
    MockMvc mvc;
    @BeforeEach void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(context.getBean(AuthLocaleFilter.class)).apply(springSecurity()).build();
    }
    private String text(String key, String language) { return messages.getMessage(key,null,Locale.forLanguageTag(language)); }
    private String html(String path, String language) throws Exception {
        return mvc.perform(get(path).param("lang",language).accept(MediaType.TEXT_HTML)).andExpect(status().isOk())
                .andExpect(header().string("Content-Language",language)).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }
    @ParameterizedTest @ValueSource(strings={"en","da","sv","nb","fr","de"})
    void allSignInPagesRenderInEveryLanguage(String language) throws Exception {
        for(var page:Map.of("/ott/login","login.heading","/ott/input","code.heading","/ott/sent","sent.heading","/logout","logout.heading").entrySet()) {
            var rendered=html(page.getKey(),language);
            assertThat(rendered).contains("lang=\""+language+"\"",text(page.getValue(),language),text("language.label",language));
            for(var supported:AuthLanguages.SUPPORTED)assertThat(rendered).contains(supported.name());
            assertThat(rendered).doesNotContain("??login.","??language.","??code.");
        }
        var magic=mvc.perform(get("/ott/input").param("token","opaque-token-value").param("lang",language))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(magic).contains("value=\"opaque-token-value\"",text("magic.subtitle",language));
        assertThat(magic).doesNotContain("id=\"ott-token\"");
        var error=mvc.perform(get("/ott/login").param("error","notify").param("lang",language))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(error).contains(text("login.error.notify",language));
    }
    @Test void choiceOverridesSavedPreferenceAndBrowserAndNorwegianAliasesNormalize() throws Exception {
        mvc.perform(get("/ott/login").param("lang","da").cookie(new Cookie(AuthLanguages.COOKIE,"de")).header("Accept-Language","fr"))
                .andExpect(header().string("Content-Language","da")).andExpect(cookie().value(AuthLanguages.COOKIE,"da"));
        mvc.perform(get("/ott/login").cookie(new Cookie(AuthLanguages.COOKIE,"de")).header("Accept-Language","fr"))
                .andExpect(header().string("Content-Language","de"));
        mvc.perform(get("/ott/login").header("Accept-Language","es,sv-SE;q=0.9"))
                .andExpect(header().string("Content-Language","sv"));
        mvc.perform(get("/ott/login").param("lang","no-NO")).andExpect(header().string("Content-Language","nb"));
        mvc.perform(get("/ott/login").param("lang","es").header("Accept-Language","es"))
                .andExpect(header().string("Content-Language","en"));
        mvc.perform(get("/ott/login").param("ui_locales","es fr-FR de")).andExpect(header().string("Content-Language","fr"));
    }
    @Test void failedLoginLogoutAndUnknownEmailKeepLanguageAndNeutralMessages() throws Exception {
        mvc.perform(post("/login/ott").with(csrf()).param("token","bad-token").param("lang","da").accept(MediaType.TEXT_HTML))
                .andExpect(redirectedUrl("/ott/login?error&lang=da"));
        mvc.perform(post("/logout").with(csrf()).param("lang","fr")).andExpect(redirectedUrl("/ott/login?logout&lang=fr"));
        when(users.getUserIdentity("nobody@example.test")).thenReturn(Optional.empty());
        mvc.perform(post("/ott/generate").with(csrf()).param("username","nobody@example.test").param("loginType","short-token").param("lang","de"))
                .andExpect(redirectedUrl("/ott/input?lang=de"));
        verify(notifications,never()).send(anyString(),anyMap());
        mvc.perform(post("/logout").param("lang","da")).andExpect(status().isForbidden());
    }
    @Test void magicLinksCarryLanguageAndSelectionPreservesTokenAndOAuthFields() throws Exception {
        when(users.getUserIdentity("user@salon.com")).thenReturn(Optional.of(MultiTenantSalonAuthzApplicationTests.TEST_USER));
        mvc.perform(post("/ott/generate").with(csrf()).param("username","user@salon.com").param("loginType","magic-link").param("lang","da"))
                .andExpect(redirectedUrl("/ott/sent?lang=da"));
        @SuppressWarnings("unchecked") ArgumentCaptor<Map<String,String>> metadata=ArgumentCaptor.forClass(Map.class);
        verify(notifications).send(eq("user@salon.com"),metadata.capture());
        assertThat(metadata.getValue()).containsEntry("language","da");
        assertThat(metadata.getValue().get("tokenLink")).contains("lang=da","token=");
        String rendered=mvc.perform(get("/ott/input").param("token","secret-link-token").param("lang","da"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(rendered).contains("name=\"token\" value=\"secret-link-token\"", "value=\"da\"");
    }
    @ParameterizedTest @ValueSource(strings={"en","da","sv","nb","fr","de"})
    void consentAndErrorPagesAreTranslatedAndDoNotLeakDiagnostics(String language) throws Exception {
        var auth=UsernamePasswordAuthenticationToken.authenticated(MultiTenantSalonAuthzApplicationTests.TEST_USER,null,MultiTenantSalonAuthzApplicationTests.TEST_USER.getAuthorities());
        var consent=mvc.perform(get("/oauth2/consent").with(authentication(auth)).param("client_id","oidc-client")
                .param("scope","openid profile").param("state","opaque-state").param("lang",language))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(consent).contains(text("consent.heading",language),text("scope.profile",language),"value=\"opaque-state\"","/oauth2/authorize");
        assertThat(consent).doesNotContain("??consent.");
        var error=mvc.perform(get("/error").param("lang",language).accept(MediaType.TEXT_HTML)
                .requestAttr(RequestDispatcher.ERROR_STATUS_CODE,404).requestAttr(RequestDispatcher.ERROR_MESSAGE,"Private diagnostic"))
                .andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(error).contains(text("error.notfound.heading",language)).doesNotContain("Private diagnostic");
    }
    @Test void consentApprovalStillUsesSpringSecurityAuthorizationState() throws Exception {
        var auth=UsernamePasswordAuthenticationToken.authenticated(MultiTenantSalonAuthzApplicationTests.TEST_USER,null,MultiTenantSalonAuthzApplicationTests.TEST_USER.getAuthorities());
        var initial=mvc.perform(get("/oauth2/authorize").with(authentication(auth)).queryParam("response_type","code").queryParam("client_id","oidc-client")
                .queryParam("scope","openid profile").queryParam("state","original-oauth-state").queryParam("redirect_uri","http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .queryParam("lang","de").queryParam("code_challenge","E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method","S256"))
                .andExpect(status().is3xxRedirection()).andReturn();
        String location=initial.getResponse().getRedirectedUrl();
        assertThat(location).contains("/oauth2/consent");
        var params=UriComponentsBuilder.fromUriString(location).build().getQueryParams();
        mvc.perform(post("/oauth2/authorize").contentType(MediaType.APPLICATION_FORM_URLENCODED).with(authentication(auth)).with(csrf()).session((MockHttpSession)initial.getRequest().getSession())
                .param("client_id","oidc-client").param("scope","profile").param("state",java.net.URLDecoder.decode(params.getFirst("state"),StandardCharsets.UTF_8)).param("lang","de"))
                .andExpect(status().is3xxRedirection()).andExpect(result->assertThat(result.getResponse().getRedirectedUrl()).contains("code=","state=original-oauth-state"));
    }
    @Test void cancellingConsentRejectsTheRequestWithoutIssuingACode() throws Exception {
        var auth=UsernamePasswordAuthenticationToken.authenticated("declining@salon.test",null,List.of());
        var initial=mvc.perform(get("/oauth2/authorize").with(authentication(auth)).queryParam("response_type","code").queryParam("client_id","oidc-client")
                .queryParam("scope","openid profile").queryParam("state","declined-original-state").queryParam("redirect_uri","http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .queryParam("code_challenge","E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method","S256"))
                .andExpect(status().is3xxRedirection()).andReturn();
        var params=UriComponentsBuilder.fromUriString(initial.getResponse().getRedirectedUrl()).build().getQueryParams();
        mvc.perform(post("/oauth2/authorize").contentType(MediaType.APPLICATION_FORM_URLENCODED).with(authentication(auth)).with(csrf())
                .session((MockHttpSession)initial.getRequest().getSession()).param("client_id","oidc-client")
                .param("state",java.net.URLDecoder.decode(params.getFirst("state"),StandardCharsets.UTF_8)))
                .andExpect(status().is3xxRedirection()).andExpect(result->assertThat(result.getResponse().getRedirectedUrl())
                        .contains("error=access_denied","state=declined-original-state").doesNotContain("code="));
    }

}
