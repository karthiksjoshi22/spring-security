package com.springSecurity.SpringSecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;

public class JWTAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter (String loginUrl , AuthenticationManager authenticationManager){

        super(new AntPathRequestMatcher(loginUrl));
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException
    {

        // validation logic goes here
        //...

        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                "test@gmail.com",
                "test123",
                new ArrayList<>())
        );
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        PrintWriter out = response.getWriter();
        JSONObject obj = new JSONObject();
        try
        {
            obj.put("status", HttpStatus.FORBIDDEN);
            obj.put("message", "Invalid Credentials");
            obj.put("errorCode","Exception");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
        catch( JSONException e )
        {
            e.printStackTrace();
        }
        out.print(obj);

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("Login Success");
        String token = Jwts.builder()
                .setSubject(((User) authResult.getPrincipal()).getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + SecurityConstant.EXPIRATION_TIME ))
                .signWith(SignatureAlgorithm.HS256, SecurityConstant.SECRET.getBytes())
                .compact();
        response.addHeader(SecurityConstant.HEADER_STRING , SecurityConstant.TOKEN_PREFIX+token);

        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("Content-Type", "application/json");

        PrintWriter out = response.getWriter();
        JSONObject obj = new JSONObject();
        try
        {
            obj.put("status", HttpStatus.OK);
            obj.put("message", "Login Successful");
            obj.put("access_token", token);
        }
        catch( JSONException e )
        {
            e.printStackTrace();
        }
        out.print(obj);
    }
}
