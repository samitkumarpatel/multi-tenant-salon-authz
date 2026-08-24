package net.samitkumar.multi_tenant_salon_authz.ott;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
class OTTController {
    @GetMapping("/ott-login")
    String login() {
        return "ott-login";
    }

    @GetMapping("/ott-login/ask-ott")
    String loginOtt(@RequestParam(name = "token", required = false) String token, Model model) {
        model.addAttribute("token", token == null ? "" : token);
        return "ott-input-form";
    }

    @GetMapping("/ott-info.html")
    String ottInfo() {
        return "ott-info";
    }
}
