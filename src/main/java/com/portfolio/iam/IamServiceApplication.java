package com.portfolio.iam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the IAM (Identity &amp; Access Management) microservice.
 *
 * <p>Provides user registration &amp; authentication with JWT access tokens and
 * rotating refresh tokens, role/group based authorization, TOTP two-factor
 * authentication, multi-tenancy and a security audit log.
 */
@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan
public class IamServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IamServiceApplication.class, args);
    }
}
