package net.samitkumar.multi_tenant_salon_authz.notification;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.samitkumar.multi_tenant_salon_authz.config.AuthLanguages;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationService {
    final MailJetClient mailJetClient;
    final MessageSource messages;
    @Value("${spring.application.mailjet.sender}") String sender;

    public void send(String to, Map<String, String> metadata) {
        var locale = Locale.forLanguageTag(AuthLanguages.normalize(metadata.get("language")).orElse("en"));
        boolean link = metadata.get("tokenLink") != null;
        String instruction = message(link ? "email.link.instruction" : "email.code.instruction", locale);
        String validity = message(link ? "email.link.validity" : "email.code.validity", locale);
        String credential = metadata.get(link ? "tokenLink" : "token");
        String help = message("email.help", locale);
        String returnToTab = link ? "" : message("email.return", locale);
        String text = message("email.welcome", locale) + "\n\n" + instruction + "\n\n" + credential
                + "\n\n" + returnToTab + "\n" + validity + "\n\n" + help + " admin@salonsaas.org";
        String escaped = HtmlUtils.htmlEscape(credential);
        String html = "<html lang=\"" + locale.getLanguage() + "\"><body><p>" + HtmlUtils.htmlEscape(message("email.greeting", locale))
                + "</p><p>" + HtmlUtils.htmlEscape(instruction) + "</p>"
                + (link ? "<p><a href=\"" + escaped + "\">" + escaped + "</a></p>"
                        : "<h2 style=\"font-size:28px;letter-spacing:4px;margin:12px 0\">" + escaped + "</h2><p>" + HtmlUtils.htmlEscape(returnToTab) + "</p>")
                + "<p>" + HtmlUtils.htmlEscape(validity) + "</p><p><small>" + HtmlUtils.htmlEscape(help)
                + " <a href=\"mailto:admin@salonsaas.org\">admin@salonsaas.org</a></small></p></body></html>";
        var request = new MailjetRequest(List.of(new MailjetMessage(new MailjetEmail(sender, "SalonSaaS"),
                List.of(new MailjetEmail(to, to)), message(link ? "email.link.subject" : "email.code.subject", locale), text, html)));
        // Never log the credential or the metadata containing it.
        log.info("Sending sign-in notification in {}", locale.getLanguage());
        mailJetClient.send(request);
    }
    private String message(String key, Locale locale) { return messages.getMessage(key, null, locale); }
}
