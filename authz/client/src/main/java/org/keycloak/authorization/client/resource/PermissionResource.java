/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authorization.client.resource;

import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.PermissionRequest;
import org.keycloak.authorization.client.representation.PermissionResponse;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionResource {

    private final Http http;
    private Configuration configuration;
    private final String pat;

    public PermissionResource(Http http, Configuration configuration, String pat) {
        this.http = http;
        this.configuration = configuration;
        this.pat = pat;
    }

    /**
     * @deprecated use {@link #create(PermissionRequest)}
     * @param request
     * @return
     */
    @Deprecated
    public PermissionResponse forResource(PermissionRequest request) {
        return create(request);
    }

    public PermissionResponse create(PermissionRequest permission) {
        try {
            return this.http.<PermissionResponse>post("/authz/protection/" + configuration.getResource() + "/permission")
                    .authorizationBearer(this.pat)
                    .json(JsonSerialization.writeValueAsBytes(permission))
                    .response().json(PermissionResponse.class).execute();
        } catch (IOException e) {
            throw new RuntimeException("Error obtaining permission ticket.", e);
        }
    }

    public PermissionResponse create(List<PermissionRequest> permissions) {
        try {
            return http.<PermissionResponse>post("/authz/protection/" + configuration.getResource() + "/permissions")
                    .authorizationBearer(this.pat)
                    .json(JsonSerialization.writeValueAsBytes(permissions))
                    .response().json(PermissionResponse.class).execute();
        } catch (IOException e) {
            throw new RuntimeException("Error obtaining permission ticket.", e);
        }
    }

    public List<PermissionTicketRepresentation> findByScope(String scopeId) {
        return Arrays.asList(http.<PermissionTicketRepresentation[]>get("/authz/protection/" + configuration.getResource() + "/permission")
                .authorizationBearer(this.pat)
                .param("scopeId", scopeId)
                .response().json(PermissionTicketRepresentation[].class).execute());
    }

    public List<PermissionTicketRepresentation> findByResource(String scopeId) {
        return Arrays.asList(http.<PermissionTicketRepresentation[]>get("/authz/protection/" + configuration.getResource() + "/permission")
                .authorizationBearer(this.pat)
                .param("resourceId", scopeId)
                .response().json(PermissionTicketRepresentation[].class).execute());
    }

    public void update(PermissionTicketRepresentation ticket) {
        try {
            http.<List>put("/authz/protection/" + configuration.getResource() + "/permission")
                    .json(JsonSerialization.writeValueAsBytes(ticket))
                    .authorizationBearer(this.pat)
                    .response().json(List.class).execute();
        } catch (IOException e) {
            throw new RuntimeException("Error updating permission ticket.", e);
        }
    }
}
