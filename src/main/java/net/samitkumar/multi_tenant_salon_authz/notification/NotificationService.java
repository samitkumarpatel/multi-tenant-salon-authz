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
        var mailFrom = new MailjetEmail(sender, "SalonSaaS");
        var tto = new MailjetEmail(to, to);
        var token = metadata.get("token");
        var tokenLink = metadata.get("tokenLink");

        var textMessage = """
                Welcome to SalonSaaS!

                Your one-time login code is:

                    %s

                Go back to the tab where you started signing in and enter this code.
                It is valid for a few minutes and can be used once.

                If that tab is gone, you can also open this link in the SAME browser
                you started from (it will not work in a different browser or device):
                %s

                If you did not request this, please report it to admin@salonsaas.org
                """.formatted(token, tokenLink);

        var htmlMessage = """
                <p>Hi,</p>
                <p>Your one-time login code for <strong>SalonSaaS</strong> is:</p>
                <h2 style="font-size:28px;letter-spacing:4px;margin:12px 0">%s</h2>
                <p>Go back to the tab where you started signing in and enter this code.
                   It is valid for a few minutes and can be used once.</p>
                <p><small>If that tab is gone, you can also
                   <a href="%s">open this link in the same browser you started from</a>
                   &mdash; it will not work in a different browser or device.</small></p>
                <p><small>If you did not request this, please contact
                   <a href="mailto:admin@salonsaas.org">admin@salonsaas.org</a></small></p>
                """.formatted(token, tokenLink);
        var request = new MailjetRequest(List.of(
                new MailjetMessage(
                        mailFrom,
                        List.of(tto),
                        "SalonSaaS OTT",
                        textMessage,
                        htmlMessage
                )
        ));

        var result = mailJetClient.send(request);
        log.info("Mailjet send result: {}", result);
    }
}
