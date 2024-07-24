package com.security.jwtoauth2.config;

import com.security.jwtoauth2.jwt.JWTFilter;
import com.security.jwtoauth2.jwt.JWTUtil;
import com.security.jwtoauth2.jwt.LoginFilter;
import com.security.jwtoauth2.jwt.LogoutFilter;
import com.security.jwtoauth2.oauth2.CustomOAuth2UserService;
import com.security.jwtoauth2.oauth2.CustomSuccessHandler;
import com.security.jwtoauth2.repository.RefreshRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        // 이게 패스워드 암호화? 맞나?
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.cors((cors) ->cors
                .configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        // 허용 주소
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        // 허용 메서드
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        // 프론트 서버에서 크리데이션 설정을 하면 여기서도 설정을 true 로 변경 해줘야함
                        configuration.setAllowCredentials(true);
                        // 허용 헤더
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        // 허용 시간
                        configuration.setMaxAge(3600L);

                        // 우리가 보낼 헤더 허용
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                }));

        // csrf disable
        http.csrf(AbstractHttpConfigurer::disable);

        // From 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable
        http.httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests((auth) -> auth
                // 모두허용
                .requestMatchers("/", "/login", "/join").permitAll()
                // refresh 토큰으로 access 토큰 발급 경로
                .requestMatchers("/reissue").permitAll()
                // 어드민 한정 허용
                .requestMatchers("/admin").hasRole("ADMIN")
                // 나머지 로그인 허용
                .anyRequest().authenticated()
        );

        // JWTFilter  추가 LoginFilter 앞에 추가
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        //oauth2
        http
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler));

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration),jwtUtil,refreshRepository), UsernamePasswordAuthenticationFilter.class);

        // 로그아웃 필터 추가? 교체?
        http.addFilterBefore(new LogoutFilter(jwtUtil, refreshRepository) , LoginFilter.class);


        // 세션 설정
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }



}
