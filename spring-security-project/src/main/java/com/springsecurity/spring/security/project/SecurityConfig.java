package com.springsecurity.spring.security.project;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasRole("USER")
                        .anyRequest().authenticated()
                )
                .formLogin((form) -> form
                        .defaultSuccessUrl("/") // Custom login page
                        .permitAll() // Allow everyone to see the login page
                )
                .logout(LogoutConfigurer::permitAll // Allow everyone to logout
                )
                .httpBasic(withDefaults()); // Enables HTTP Basic Authentication

        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        // Defining a simple in-memory user and admin with roles
        UserDetails user = User.withUsername("user").password(passwordEncoder().encode("123")).roles("USER").build();

        UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("123")).roles("ADMIN").build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}
