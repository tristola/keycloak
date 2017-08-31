/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.authorization.policy.evaluation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class PermissionTicketAwareDecisionResultCollector extends DecisionResultCollector {

    private Identity identity;
    private AuthorizationProvider authorization;

    public PermissionTicketAwareDecisionResultCollector(Identity identity, AuthorizationProvider authorization) {
        this.identity = identity;
        this.authorization = authorization;
    }

    @Override
    protected void onDeny(Result result) {
        ResourcePermission permission = result.getPermission();
        Resource resource = permission.getResource();

        if (resource != null && resource.isOwnerManagedAccess()) {
            Map<String, String> filters = new HashMap<>();

            filters.put(PermissionTicket.RESOURCE, resource.getId());
            filters.put(PermissionTicket.REQUESTER, identity.getId());
            filters.put(PermissionTicket.GRANTED, Boolean.TRUE.toString());

            List<PermissionTicket> permissions = authorization.getStoreFactory().getPermissionTicketStore().find(filters, resource.getResourceServer().getId(), -1, -1);

            if (!permissions.isEmpty()) {
                List<Scope> permissionScopes = permission.getScopes();
                List<Result.PolicyResult> results = result.getResults();

                for (Result.PolicyResult policyResult : results) {
                    if (policyResult.getPolicy().getType().equals("resource")) {
                        policyResult.setStatus(Effect.PERMIT);
                        for (PermissionTicket ticket : permissions) {
                            Scope grantedScope = ticket.getScope();

                            if (grantedScope != null) {
                                policyResult.addScope(grantedScope);
                            }
                        }
                    } else {
                        if (!permissionScopes.isEmpty()) {
                            for (PermissionTicket ticket : permissions) {
                                Scope grantedScope = ticket.getScope();

                                if (grantedScope != null) {
                                    Set<Scope> policyScopes = policyResult.getPolicy().getScopes();

                                    for (Scope policyScope : policyScopes) {
                                        if (policyScope.equals(grantedScope)) {
                                            policyResult.setStatus(Effect.PERMIT);
                                        }
                                    }

                                    if (Effect.PERMIT.equals(policyResult.getStatus())) {
                                        policyResult.addScope(grantedScope);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        super.onDeny(result);
    }
}
