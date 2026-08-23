package net.samitkumar.multi_tenant_salon_authz.notification;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

record MailjetMessage(
        @JsonProperty("From") MailjetEmail from,
        @JsonProperty("To") List<MailjetEmail> to,
        @JsonProperty("Subject") String subject,
        @JsonProperty("TextPart") String textPart,
        @JsonProperty("HTMLPart") String htmlPart) {
}
