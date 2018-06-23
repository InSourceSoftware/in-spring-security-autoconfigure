package io.insource.springboot.security;

import io.insource.springboot.security.annotation.EnableBasicAuth;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.Base64Utils;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ContextConfiguration
@WebAppConfiguration
@EnableAutoConfiguration
public class BasicAuthenticationAutoConfigurationTest {
    @Autowired
    private WebApplicationContext applicationContext;

    private MockMvc mockMvc;

    @Before
    public void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
            .apply(springSecurity())
            .build();
    }

    @Test
    public void testGet() throws Exception {
        mockMvc.perform(get("/")
            .header("Authorization", String.format("Basic %s", Base64Utils.encodeToString("user:password".getBytes())))
        )
            .andExpect(status().is(200))
            .andExpect(content().string("OK"));
    }

    @Test
    public void testGet_401_Unauthorized() throws Exception {
        mockMvc.perform(get("/"))
            .andExpect(status().is(401));
    }

    @Test
    public void testPost() throws Exception {
        mockMvc.perform(post("/")
            .header("Authorization", String.format("Basic %s", Base64Utils.encodeToString("user:password".getBytes())))
            .with(csrf().asHeader())
            .content("test")
        )
            .andExpect(status().is(200))
            .andExpect(content().string("OK test"));
    }

    @Configuration
    @EnableBasicAuth
    public static class Config {
    }
}
