package br.com.nunesmaia.messias.resourceserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class MessagesController {

	@GetMapping()
	public String getMessages() {
		return "You got it !";
	}
}
