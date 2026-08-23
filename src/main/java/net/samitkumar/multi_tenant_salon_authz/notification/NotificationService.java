package net.samitkumar.multi_tenant_salon_authz.notification;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationService {
    final MailJetClient mailJetClient;
    @Value("${spring.application.mailjet.sender}")
    String sender;

    public void send(String to, Map<String, String> metadata) {
        log.info("Sending Mailjet notification to {} with metadata {}", to, metadata);
        var mailFrom = new MailjetEmail(sender, "My Salon");
        var tto = new MailjetEmail(to, to);
        var token = metadata.get("token");
        var tokenLink = metadata.get("tokenLink");

        var textMessage = """
                Welcome to My Salon!
                
                Your one-time login token is: %s
                
                Use the link below to sign in (copy and paste into your browser if it does not open):
                %s
                
                If you did not request this, please report it to admin@salonsaas.org
                """.formatted(token, tokenLink);

        var htmlMessage = """
                <p>Hi,</p>
                <p>Your one-time login token for <strong>My Salon</strong> is:</p>
                <h2>%s</h2>
                <p>Or sign in directly: <a href="%s">%s</a></p>
                <p><small>If you did not request this, please contact <a href="mailto:admin@salonsaas.org">admin@salonsaas.org</a></small></p>
                """.formatted(token, tokenLink, tokenLink);
        var request = new MailjetRequest(List.of(
                new MailjetMessage(
                        mailFrom,
                        List.of(tto),
                        "SaloonSaaS OTT",
                        textMessage,
                        htmlMessage
                )
        ));

        var result = mailJetClient.send(request);
        log.info("Mailjet send result: {}", result);
    }
}
