package net.samitkumar.multi_tenant_salon_authz.notification;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.support.ResourceBundleMessageSource;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class NotificationI18nTest {
    @Test void everyCatalogHasMatchingKeysAndPlaceholders() throws Exception {
        Properties base=properties("messages.properties");
        for(String code:List.of("da","sv","nb","fr","de")) {
            Properties translated=properties("messages_"+code+".properties");
            assertThat(translated.keySet()).isEqualTo(base.keySet());
            for(String key:base.stringPropertyNames()) {
                assertThat(translated.getProperty(key)).isNotBlank();
                for(String placeholder:List.of("{0}","{1}"))assertThat(translated.getProperty(key).contains(placeholder)).as(code+":"+key).isEqualTo(base.getProperty(key).contains(placeholder));
            }
        }
    }
    private Properties properties(String file) throws Exception {
        var result=new Properties();
        try(var stream=getClass().getResourceAsStream("/"+file)) { result.load(new InputStreamReader(stream,StandardCharsets.UTF_8)); }
        return result;
    }
    @Test void emailSubjectAndBodiesUseChosenLanguageAndEscapeHtml() {
        var messages=new ResourceBundleMessageSource();messages.setBasename("messages");messages.setDefaultEncoding("UTF-8");messages.setFallbackToSystemLocale(false);
        for(String language:List.of("en","da","sv","nb","fr","de"))for(boolean link:List.of(false,true)) {
            var mail=mock(MailJetClient.class);var service=new NotificationService(mail,messages);service.sender="noreply@example.test";
            var metadata=new HashMap<String,String>();metadata.put("language",language);metadata.put("token","123456");
            if(link)metadata.put("tokenLink","https://auth.test/ott/input?token=opaque&lang="+language);
            service.send("user@example.test",metadata);
            var captor=ArgumentCaptor.forClass(MailjetRequest.class);verify(mail).send(captor.capture());
            var sent=captor.getValue().messages().getFirst();
            assertThat(sent.subject()).isEqualTo(messages.getMessage(link?"email.link.subject":"email.code.subject",null,Locale.forLanguageTag(language)));
            assertThat(sent.htmlPart()).contains("lang=\""+language+"\"");
            assertThat(sent.textPart()).contains(link?metadata.get("tokenLink"):"123456");
            if(link)assertThat(sent.htmlPart()).contains("&amp;lang=");
        }
    }
}
