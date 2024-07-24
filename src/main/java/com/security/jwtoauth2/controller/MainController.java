package com.security.jwtoauth2.controller;

import com.security.jwtoauth2.dto.UserDTO;
import com.security.jwtoauth2.jwt.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collection;
import java.util.Iterator;

@Controller
//@ResponseBody
@RequiredArgsConstructor
public class MainController {

    private final JWTUtil jwtUtil;

    @GetMapping("/")
    public String mainPage(HttpServletRequest request,Model model){

        // 이건 refresh 토큰 사용 방법
        UserDTO user = jwtUtil.getUser(request);

        System.out.println("name = " + user.getName());
        System.out.println("role = " + user.getRole());

        model.addAttribute("name", user.getName());
        model.addAttribute("role", user.getRole());


        return "/main";
    }

    @GetMapping("/API")
    @ResponseBody
    public String mainAPI(){


        // 이건 access 토큰으로 가져오는 방법
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        return "Main Controller : " + name + ", role : " + role;
    }

    @GetMapping("/loginPage")
    public String loginPage(){

        return "/login";
    }



}