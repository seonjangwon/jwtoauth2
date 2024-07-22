package com.security.jwtoauth2.jwt;


import com.security.jwtoauth2.dto.jwt.CustomUserDetails;
import com.security.jwtoauth2.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        /**
         * 이전 버전
         String authorization = request.getHeader("Authorization");

         if (authorization == null || !authorization.startsWith("Bearer")) {

         System.out.println("token null");
         filterChain.doFilter(request, response);

         //조건에 해당 되면 메소드 종료
         return;
         }

         String token = authorization.split(" ")[1];

         // 토큰 소멸 시간 검증

         if (jwtUtil.isExpired(token)) {
         System.out.println("token expired");
         filterChain.doFilter(request,response);

         //조건에 해당 되면 메소드 종료
         return;
         }

         // 토큰에서 값 추출
         String username = jwtUtil.getUsername(token);
         String role = jwtUtil.getRole(token);

         // userEntity  생성 값 세팅
         UserEntity userEntity = new UserEntity();
         userEntity.setUsername(username);
         userEntity.setPassword("tem password");
         userEntity.setRole(role);

         // 회원 정보와 객체 담기
         CustomUserDetails details = new CustomUserDetails(userEntity);

         // 스프링 시큐리티 인증 토큰 생성
         Authentication authToken = new UsernamePasswordAuthenticationToken(details, null, details.getAuthorities());
         // 세션에 사용자 등록
         SecurityContextHolder.getContext().setAuthentication(authToken);

         filterChain.doFilter(request,response);
         */

        // 헤더에서 access 키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            filterChain.doFilter(request,response);
            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필러토 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {

            // response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            // response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 토큰이 access 인지 확인 (발급 시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")){

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            // response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails,null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request,response);
    }
}
