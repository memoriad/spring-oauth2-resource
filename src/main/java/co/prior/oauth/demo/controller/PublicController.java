package co.prior.oauth.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("public")
public class PublicController {

	@GetMapping("/welcome")
	public @ResponseBody String getGreeting() {
		return "Hey Good Day!";
	}

}