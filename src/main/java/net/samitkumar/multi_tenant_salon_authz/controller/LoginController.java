package net.samitkumar.multi_tenant_salon_authz.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
class LoginController {
    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/login/ask-ott")
    String loginOtt(@RequestParam(name = "token", required = false) String token, Model model) {
        model.addAttribute("token", token == null ? "" : token);
        return "login-ott";
    }

    @GetMapping("/ott-info.html")
    String ottInfo() {
        return "ott-info";
    }
}
