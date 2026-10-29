package net.samitkumar.multi_tenant_salon_authz.ott;

import jakarta.servlet.http.HttpServletRequest;
import net.samitkumar.multi_tenant_salon_authz.config.AuthLanguages;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import java.util.ArrayList;
import java.util.List;

@ControllerAdvice
class AuthPageAdvice {
    record Parameter(String name, String value) {}
    @ModelAttribute void languages(HttpServletRequest request, Model model) {
        model.addAttribute("supportedLanguages", AuthLanguages.SUPPORTED);
        model.addAttribute("currentLanguage", AuthLanguages.resolve(request).getLanguage());
        model.addAttribute("languagePath", request.getRequestURI());
        List<Parameter> parameters = new ArrayList<>();
        request.getParameterMap().forEach((name, values) -> {
            if (!List.of("lang", "_csrf", "username", "loginType").contains(name))
                for (String value : values) parameters.add(new Parameter(name, value));
        });
        model.addAttribute("languageParameters", parameters);
    }
}
