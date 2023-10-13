package com.ead.serviceregistry.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static jakarta.servlet.DispatcherType.ERROR;

@Configuration
public class WebSecurityConfig {

    private final String username;
    private final String password;

    public WebSecurityConfig(@Value("${ead.service-registry.username}") final String username,
                             @Value("${ead.service-registry.password}")final String password) {
        this.username = username;
        this.password = password;
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        return http
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                    .dispatcherTypeMatchers(ERROR).permitAll()
                    .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        var user = User.withUsername(username)
                .password(passwordEncoder().encode(password))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
