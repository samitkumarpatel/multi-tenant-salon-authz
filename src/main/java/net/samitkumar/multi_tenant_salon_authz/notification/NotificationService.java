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
        // var tokenLink = metadata.get("tokenLink"); // disabled magic-link path — see below

        var textMessage = """
                Welcome to SalonSaaS!

                Your one-time login code is:

                    %s

                Go back to the tab where you started signing in and enter this code.
                It is valid for a few minutes and can be used once.

                If you did not request this, please report it to admin@salonsaas.org
                """.formatted(token);

        var htmlMessage = """
                <p>Hi,</p>
                <p>Your one-time login code for <strong>SalonSaaS</strong> is:</p>
                <h2 style="font-size:28px;letter-spacing:4px;margin:12px 0">%s</h2>
                <p>Go back to the tab where you started signing in and enter this code.
                   It is valid for a few minutes and can be used once.</p>
                <p><small>If you did not request this, please contact
                   <a href="mailto:admin@salonsaas.org">admin@salonsaas.org</a></small></p>
                """.formatted(token);

        // ── Disabled: magic-link email body ─────────────────────────────────────
        // The emailed link opens a different browser/tab than the one that started
        // the OAuth2 + PKCE flow, so the client loses its state/code_verifier and
        // shows "Sign-in expired". We now email only the code (above). To re-enable,
        // restore "tokenLink" above and use these message bodies instead:
        //
        // var textMessage = """
        //         Welcome to SalonSaaS!
        //
        //         Your one-time login token is: %s
        //
        //         Use the link below to sign in (copy and paste into your browser if it does not open):
        //         %s
        //
        //         If you did not request this, please report it to admin@salonsaas.org
        //         """.formatted(token, tokenLink);
        //
        // var htmlMessage = """
        //         <p>Hi,</p>
        //         <p>Your one-time login token for <strong>SalonSaaS</strong> is:</p>
        //         <h2>%s</h2>
        //         <p>Or sign in directly: <a href="%s">%s</a></p>
        //         <p><small>If you did not request this, please contact <a href="mailto:admin@salonsaas.org">admin@salonsaas.org</a></small></p>
        //         """.formatted(token, tokenLink, tokenLink);
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
