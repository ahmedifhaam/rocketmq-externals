/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.rocketmq.console.controller;

import com.google.common.collect.Maps;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/user")
public class LoginController {
    private Logger logger = LoggerFactory.getLogger(LoginController.class);
    
    
    //Api for checking the logged in user details 
    //currently provides only user name
    //: Have to add user roles and permissions in the response
    @RequiresAuthentication
    @RequestMapping(value = "/me",method = RequestMethod.GET)
    @ResponseBody
    public Object me() {
        Map<String,Object> out = Maps.newHashMap(); 
        final Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            out.put("user", subject.getPrincipal());
        }
        return out;
    }
    
    //API for logging in the user 
    @RequestMapping(value = "/me", method = {RequestMethod.POST})
    @ResponseBody
    public Object login(@RequestHeader(value = "Authorization") String auth) {
        Map<String,String> out = Maps.newHashMap(); 
        logger.info("reached");
        if (auth != null) {
            logger.info("header :" + auth);
            //split user name password 
            String[] userNameandPass = decodeAutherization(auth);

            final Subject subject = SecurityUtils.getSubject();
            logger.info("Username " + userNameandPass[0]);
            subject.login(new UsernamePasswordToken(userNameandPass[0],userNameandPass[1]));
            
            out.put("username", userNameandPass[0]);
            if (subject.isAuthenticated()) out.put("status", "Authenticated");
            else out.put("status", "Authentication failed");
        } else {
            out.put("status","Invalid Credentials");
        }
        
       
        return out;
    }
    
    
    //API for logging out the currently logged in user
    @RequestMapping(value = "/logout",method = {RequestMethod.GET})
    @ResponseBody
    public Object logout() {
        Map<String,String> out = Maps.newHashMap();
        final Subject subject = SecurityUtils.getSubject();
        subject.logout();
        if (!subject.isAuthenticated()) out.put("status", "SUCCESS");
        else out.put("status", "FAILED");
        
        return out;
    }
    
    //splits username and password and returns in a array
    //where username in first index(0) and password in seconnd index(1)
    public String[] decodeAutherization(String base64String) {
        String encodedUserAndPass = base64String.substring("Basic".length()).trim();
        String credentials = new String(Base64.getDecoder().decode(encodedUserAndPass),Charset.forName("UTF-8"));
        String[] values = credentials.split(":",2);
        return values;
    }
}
