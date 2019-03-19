package com.springSecurity.SpringSecurity.security;


public class SecurityConstant {

    private SecurityConstant()
    {
    }

    public static final String SECRET = "qqGBIHPqq";
    public static final long EXPIRATION_TIME = 4 * 60 * 60 * 1000L; // 30 days
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";

}
