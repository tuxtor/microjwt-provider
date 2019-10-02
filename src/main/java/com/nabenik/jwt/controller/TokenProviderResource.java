package com.nabenik.jwt.controller;

import com.nabenik.jwt.auth.CypherService;
import com.nabenik.jwt.auth.RolesEnum;


import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;

@Singleton
@Path("/auth")
public class TokenProviderResource {

    @Inject
    CypherService cypherService;

    private PrivateKey key;

    @PostConstruct
    public void init() {
        try {
            key = cypherService.readPrivateKey();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response doPosLogin(@FormParam("username") String username, @FormParam("password")String password,
                               @Context HttpServletRequest request){

        List<String> target = new ArrayList<>();
        try {
            request.login(username, password);

            if(request.isUserInRole(RolesEnum.MOBILE.getRole()))
                target.add(RolesEnum.MOBILE.getRole());

            if(request.isUserInRole(RolesEnum.WEB.getRole()))
                target.add(RolesEnum.WEB.getRole());

        }catch (ServletException ex){
            ex.printStackTrace();
            return Response.status(Response.Status.UNAUTHORIZED)
                    .build();
        }

        String token = cypherService.generateJWT(key, username, target);

            return Response.status(Response.Status.OK)
                    .header(AUTHORIZATION, "Bearer ".concat(token))
                    .entity(token)
                    .build();

    }

}
