package com.atomic.coding.authorizationserver.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/greeting")
class GreetingController {

    @GetMapping
    fun greeting(
        @RequestParam(value = "name", required = false) name: String?
    ): String = "Hello, $name!"


}