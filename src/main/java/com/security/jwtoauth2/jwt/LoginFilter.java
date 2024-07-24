package com.security.jwtoauth2.jwt;


import com.security.jwtoauth2.entity.RefreshEntity;
import com.security.jwtoauth2.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * 그니까 스프링 시큐리티를 설정하면 지정 Form에서 가져와서 로그인을 하는데
     * 우리는 form 로그인을 막아뒀으니까
     * 우리가 맞게 검증을 하는 필터를 만드는 과정
     */


    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    /**
     * 받아오는 username, password 두가지를 검증해주는 과정
     * @param request
     * @param response
     * @return
     * @throws ArithmeticException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws ArithmeticException {

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username = " + username);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password, null);

        return authenticationManager.authenticate(authToken);
    }


    //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        /**
         * 여기는 그냥 토큰만 발급 과정
         CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

         String username = customUserDetails.getUsername();

         Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
         Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
         GrantedAuthority auth = iterator.next();

         String role = auth.getAuthority();


         String token = jwtUtil.createJwt(username, role, 60*60*10L);

         response.addHeader("Authorization", "Bearer "+token);
         */

        /**
         * Refresh / Access 두가지 토큰 발급 과정
         */

        // 유저 정보
        String username = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // 토큰 생성
        String access = jwtUtil.createJwt("access",username,role, 600000L);
        String refresh = jwtUtil.createJwt("refresh",username,role, 600000L);

        // refresh 토큰 저장
        addRefreshEntity(username, refresh, 86400000L);

        response.setHeader("access",access); // 로컬스토리지 저장
        response.addCookie(createCookie("refresh",refresh)); // httpOnly 쿠키 저장
        response.setStatus(HttpStatus.OK.value());

    }

    private void addRefreshEntity(String username, String refresh, Long expireMs){

        Date date = new Date(System.currentTimeMillis() + expireMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }

    private Cookie createCookie(String key, String value){
        Cookie cookie = new Cookie(key,value);
        cookie.setMaxAge(24*60*60);
        cookie.setSecure(true); // 이거는 https 로 진행 시 넣어준다
        cookie.setPath("/"); // 사용될 범위 지정?
        cookie.setHttpOnly(true); // 자바 스크립트에서 사용 못하도록 설정

        return cookie;
    }


}
