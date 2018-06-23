package io.insource.springboot.security.controller;

import io.insource.springboot.security.annotation.EnableCsrfEndpoint;
import io.insource.springboot.security.condition.EnableAnnotationCondition;

import org.springframework.context.annotation.Conditional;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Conditional(CsrfController.EnableCsrfEndpointCondition.class)
public class CsrfController {
    @GetMapping("/csrf")
    public CsrfToken csrf(CsrfToken csrfToken) {
        return csrfToken;
    }

    public static class EnableCsrfEndpointCondition extends EnableAnnotationCondition<EnableCsrfEndpoint> {
        public EnableCsrfEndpointCondition() {
            super(EnableCsrfEndpoint.class);
        }

        @Override
        protected String getPrefix() {
            return "security.auth.csrf";
        }
    }
}
