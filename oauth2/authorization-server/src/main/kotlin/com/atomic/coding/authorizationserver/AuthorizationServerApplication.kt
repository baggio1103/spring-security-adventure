package com.atomic.coding.authorizationserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class AuthorizationServerApplication

fun main(args: Array<String>) {
    runApplication<AuthorizationServerApplication>(*args)
}
