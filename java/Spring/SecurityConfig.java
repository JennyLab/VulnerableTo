/*
   Spring: Vulnerable to CSRF

*/

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF
        http.csrf().disable() 
            .authorizeRequests().anyRequest().authenticated();
        return http.build();
    }
}
