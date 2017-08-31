/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authorization.authorization;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.authorization.representation.AuthorizationRequest;
import org.keycloak.authorization.authorization.representation.AuthorizationResponse;
import org.keycloak.authorization.common.KeycloakEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.PermissionTicketAwareDecisionResultCollector;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.authorization.protection.permission.PermissionTicketToken;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.authorization.util.Permissions;
import org.keycloak.authorization.util.Tokens;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.Consumes;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationTokenService {

    protected static final Logger logger = Logger.getLogger(AuthorizationTokenService.class);
    private static Map<String, BiFunction<AuthorizationRequest, AuthorizationProvider, KeycloakEvaluationContext>> SUPPORTED_CLAIM_TOKEN_FORMATS;

    static {
        SUPPORTED_CLAIM_TOKEN_FORMATS = new HashMap<>();
        SUPPORTED_CLAIM_TOKEN_FORMATS.put("http://openid.net/specs/openid-connect-core-1_0.html#IDToken", (authorizationRequest, authorization) -> new KeycloakEvaluationContext(authorizationRequest.getClaimToken(), authorization.getKeycloakSession()));

        //TODO: this will be removed once we stop supporting UMA 1
        SUPPORTED_CLAIM_TOKEN_FORMATS.put("UMA1", (authorizationRequest, authorization) -> {
            KeycloakEvaluationContext evaluationContext = new KeycloakEvaluationContext(authorization.getKeycloakSession());

            if (!evaluationContext.getIdentity().hasRealmRole("uma_authorization")) {
                throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires uma_authorization scope.", Status.FORBIDDEN);
            }

            return evaluationContext;
        });
    }

    private final AuthorizationProvider authorization;

    @Context
    private HttpRequest httpRequest;

    @Context
    private KeycloakSession session;

    public AuthorizationTokenService(AuthorizationProvider authorization) {
        this.authorization = authorization;
    }

    @OPTIONS
    public Response authorizepPreFlight() {
        return Cors.add(httpRequest, Response.ok()).auth().preflight().build();
    }

    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorize(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Invalid authorization request.", Status.BAD_REQUEST);
        }

        PermissionTicketToken ticket = verifyPermissionTicket(authorizationRequest);
        String claimToken = authorizationRequest.getClaimToken();
        String claimTokenFormat = "UMA1";

        if (claimToken != null) {
            claimTokenFormat = authorizationRequest.getClaimTokenFormat();

            if (claimTokenFormat == null) {
                claimTokenFormat = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken";
            }
        }

        BiFunction<AuthorizationRequest, AuthorizationProvider, KeycloakEvaluationContext> evaluationContextProvider = SUPPORTED_CLAIM_TOKEN_FORMATS.get(claimTokenFormat);

        if (evaluationContextProvider == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Claim token format [" + claimTokenFormat + "] not supported", Status.BAD_REQUEST);
        }

        KeycloakEvaluationContext evaluationContext = evaluationContextProvider.apply(authorizationRequest, authorization);

        try {
            ResourceServer resourceServer = authorization.getStoreFactory().getResourceServerStore().findById(ticket.getResourceServerId());

            if (resourceServer == null) {
                throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Client does not support permissions", Status.FORBIDDEN);
            }

            AtomicReference<List<Result>> result = new AtomicReference<>();

            authorization.evaluators().from(createPermissions(ticket, authorizationRequest, resourceServer, authorization), evaluationContext).evaluate(new PermissionTicketAwareDecisionResultCollector(evaluationContext.getIdentity(), authorization) {
                @Override
                protected void onComplete(List<Result> results) {
                    result.set(results);
                }
            });

            List<Permission> entitlements = Permissions.permits(result.get(), authorization, resourceServer);

            if (entitlements.isEmpty()) {
                throw new ErrorResponseException(OAuthErrorException.ACCESS_DENIED, "not_authorized", Status.FORBIDDEN);
            }

            KeycloakIdentity identity = (KeycloakIdentity) evaluationContext.getIdentity();
            String rpt = createRequestingPartyToken(entitlements, identity.getAccessToken(), resourceServer);
            AuthorizationResponse response;

            // TODO: if there is a claim token we assume client is using UMA Grant Type and version 2.0.
            if (claimToken != null) {
                response = new AuthorizationResponse();
                response.setToken(rpt);
                response.setTokenType("bearer");
                if (authorizationRequest.getRpt() != null) {
                    response.setUpgraded(true);
                }
            } else {
                response = new AuthorizationResponse();
                response.setRpt(rpt);
            }

            return Cors.add(httpRequest, Response.status(Status.CREATED).type(MediaType.APPLICATION_JSON_TYPE).entity(response))
                    .allowedOrigins(identity.getAccessToken())
                    .allowedMethods("POST")
                    .exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS).build();
        } catch (ErrorResponseException cause) {
            logger.error("Error while evaluating permissions", cause);
            throw cause;
        } catch (Exception cause) {
            logger.error("Error while evaluating permissions", cause);
            throw new ErrorResponseException(OAuthErrorException.SERVER_ERROR, "Error while evaluating permissions", Status.INTERNAL_SERVER_ERROR);
        }
    }

    private List<ResourcePermission> createPermissions(PermissionTicketToken ticket, AuthorizationRequest request, ResourceServer resourceServer, AuthorizationProvider authorization) {
        StoreFactory storeFactory = authorization.getStoreFactory();
        Map<String, Set<String>> permissionsToEvaluate = new HashMap<>();
        ResourceStore resourceStore = storeFactory.getResourceStore();

        for (PermissionTicketToken.ResourcePermission requestedResource : ticket.getResources()) {
            Set<String> requestedScopes = requestedResource.getScopes();
            Resource existingResource = null;

            if (requestedResource.getResourceId() != null) {
                existingResource = resourceStore.findById(requestedResource.getResourceId(), resourceServer.getId());

                if (existingResource == null) {
                    existingResource = resourceStore.findByName(requestedResource.getResourceId(), resourceServer.getId());
                }
            } else {
                String ticketId = requestedResource.getTicket();

                if (ticketId != null) {
                    org.keycloak.authorization.model.PermissionTicket permissionTicket = storeFactory.getPermissionTicketStore().findById(ticketId, resourceServer.getId());
                    existingResource = permissionTicket.getResource();
                    if (permissionTicket.getScope() != null) {
                        requestedScopes = new HashSet<>();
                        requestedScopes.add(permissionTicket.getScope().getId());
                    }
                }
            }

            if (existingResource == null && (requestedScopes == null || requestedScopes.isEmpty())) {
                throw new ErrorResponseException("invalid_resource", "Resource with id [" + requestedResource.getResourceId() + "] does not exist.", Status.FORBIDDEN);
            }

            String clientAdditionalScopes = request.getScope();

            if (clientAdditionalScopes != null) {
                requestedScopes.addAll(Arrays.asList(clientAdditionalScopes.split(" ")));
            }

            if (existingResource != null) {
                Set<String> scopes = permissionsToEvaluate.get(existingResource.getId());

                if (scopes == null) {
                    scopes = new HashSet<>();
                    permissionsToEvaluate.put(existingResource.getId(), scopes);
                }

                scopes.addAll(requestedScopes);
            } else {
                List<Resource> resources = resourceStore.findByScope(new ArrayList<>(requestedScopes), ticket.getResourceServerId());

                for (Resource resource : resources) {
                    permissionsToEvaluate.put(resource.getId(), requestedScopes);
                }

                permissionsToEvaluate.put("$KC_SCOPE_PERMISSION", requestedScopes);
            }
        }

        String rpt = request.getRpt();

        if (rpt != null) {
            if (!Tokens.verifySignature(session, getRealm(), rpt)) {
                throw new ErrorResponseException("invalid_rpt", "RPT signature is invalid", Status.FORBIDDEN);
            }

            AccessToken requestingPartyToken;

            try {
                requestingPartyToken = new JWSInput(rpt).readJsonContent(AccessToken.class);
            } catch (JWSInputException e) {
                throw new ErrorResponseException("invalid_rpt", "Invalid RPT", Status.FORBIDDEN);
            }

            if (requestingPartyToken.isActive()) {
                AccessToken.Authorization authorizationData = requestingPartyToken.getAuthorization();

                if (authorizationData != null) {
                    List<Permission> permissions = authorizationData.getPermissions();

                    if (permissions != null) {
                        permissions.forEach(permission -> {
                            Resource resourcePermission = resourceStore.findById(permission.getResourceSetId(), ticket.getResourceServerId());

                            if (resourcePermission != null) {
                                Set<String> scopes = permissionsToEvaluate.get(resourcePermission.getId());

                                if (scopes == null) {
                                    scopes = new HashSet<>();
                                    permissionsToEvaluate.put(resourcePermission.getId(), scopes);
                                }

                                Set<String> scopePermission = permission.getScopes();

                                if (scopePermission != null) {
                                    scopes.addAll(scopePermission);
                                }
                            }
                        });
                    }
                }
            }
        }

        ScopeStore scopeStore = storeFactory.getScopeStore();

        return permissionsToEvaluate.entrySet().stream()
                .flatMap((Function<Entry<String, Set<String>>, Stream<ResourcePermission>>) entry -> {
                    String key = entry.getKey();
                    if ("$KC_SCOPE_PERMISSION".equals(key)) {
                        List<Scope> scopes = entry.getValue().stream().map(scopeName -> scopeStore.findByName(scopeName, resourceServer.getId())).filter(scope -> Objects.nonNull(scope)).collect(Collectors.toList());
                        return Arrays.asList(new ResourcePermission(null, scopes, resourceServer)).stream();
                    } else {
                        Resource entryResource = resourceStore.findById(key, resourceServer.getId());
                        return Permissions.createResourcePermissions(entryResource, entry.getValue(), authorization).stream();
                    }
                }).collect(Collectors.toList());
    }

    private RealmModel getRealm() {
        return this.authorization.getKeycloakSession().getContext().getRealm();
    }

    private String createRequestingPartyToken(List<Permission> permissions, AccessToken accessToken, ResourceServer resourceServer) {
        AccessToken.Authorization authorization = new AccessToken.Authorization();

        authorization.setPermissions(permissions);
        accessToken.setAuthorization(authorization);

        ClientModel clientModel = getRealm().getClientById(resourceServer.getClientId());

        if (!accessToken.hasAudience(clientModel.getClientId())) {
            accessToken.audience(clientModel.getClientId());
        }

        return new TokenManager().encodeToken(session, getRealm(), accessToken);
    }

    private PermissionTicketToken verifyPermissionTicket(AuthorizationRequest request) {
        String ticketString = request.getTicket();

        if (ticketString == null || !Tokens.verifySignature(session, getRealm(), ticketString)) {
            throw new ErrorResponseException("invalid_ticket", "Ticket verification failed", Status.FORBIDDEN);
        }

        try {
            PermissionTicketToken ticket = new JWSInput(ticketString).readJsonContent(PermissionTicketToken.class);

            if (!ticket.isActive()) {
                throw new ErrorResponseException("invalid_ticket", "Invalid permission ticket.", Status.FORBIDDEN);
            }

            return ticket;
        } catch (JWSInputException e) {
            throw new ErrorResponseException("invalid_ticket", "Could not parse permission ticket.", Status.FORBIDDEN);
        }
    }
}
