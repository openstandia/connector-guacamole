/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.guacamole;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static jp.openstandia.connector.guacamole.GuacamoleUtils.*;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;

public class GuacamoleUserGroupHandler implements GuacamoleObjectHandler {

    public static final ObjectClass USER_GROUP_OBJECT_CLASS = new ObjectClass("UserGroup");

    private static final Log LOGGER = Log.getLog(GuacamoleUserGroupHandler.class);

    // Unique and unchangeable within the guacamole server
    // Also, it's case-sensitive
    private static final String ATTR_GROUP_NAME = "identifier";

    // Attributes
    // Nothing

    // Permissions
    static final String ATTR_SYSTEM_PERMISSIONS = "systemPermissions";

    // Activation
    private static final String ATTR_DISABLED = "disabled";

    // Association
    private static final String ATTR_USERS = "users";
    private static final String ATTR_USER_GROUPS = "userGroups";
    private static final String ATTR_CONNECTIONS = "connections";
    private static final String ATTR_CONNECTION_GROUPS = "connectionGroups";

    private final GuacamoleConfiguration configuration;
    private final GuacamoleClient client;
    private final GuacamoleSchema schema;
    private final GuacamoleAssociationHandler associationHandler;

    public GuacamoleUserGroupHandler(GuacamoleConfiguration configuration, GuacamoleClient client) {
        this.configuration = configuration;
        this.client = client;
        this.schema = new GuacamoleSchema(configuration, client);
        this.associationHandler = new GuacamoleAssociationHandler(configuration, client);
    }

    public static ObjectClassInfo createSchema() {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(USER_GROUP_OBJECT_CLASS.getObjectClassValue());

        // __UID__ and __NAME__ are the same
        // identifier __UID__
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Uid.NAME)
                        .setRequired(false)
                        .setCreateable(false)
                        .setUpdateable(false)
                        .setNativeName(ATTR_GROUP_NAME)
                        .build());
        // identifier __NAME__
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Name.NAME)
                        .setRequired(true)
                        .setUpdateable(false)
                        .setNativeName(ATTR_GROUP_NAME)
                        .build());

        // Permissions
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_SYSTEM_PERMISSIONS)
                        .setRequired(false) // Must be optional
                        .setCreateable(true)
                        .setUpdateable(true)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build());

        // Association
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_USERS)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .setCreateable(false)
                        .setUpdateable(false)
                        .build());
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_USER_GROUPS)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build());
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_CONNECTIONS)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build());
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_CONNECTION_GROUPS)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build());

        ObjectClassInfo groupSchemaInfo = builder.build();

        LOGGER.info("The constructed UserGroup core schema: {0}", groupSchemaInfo);

        return groupSchemaInfo;
    }

    /**
     * @param attributes
     * @return
     * @throws AlreadyExistsException Object with the specified _NAME_ already exists.
     *                                Or there is a similar violation in any of the object attributes that
     *                                cannot be distinguished from AlreadyExists situation.
     */
    @Override
    public Uid create(Set<Attribute> attributes) throws AlreadyExistsException {
        Set<Attribute> groupAttrs = new HashSet<>();
        List<Object> addGroups = null;
        List<Object> addConnections = null;
        List<Object> addConnectionGroups = null;
        List<Object> systemPermissions = null;

        for (Attribute attr : attributes) {
            if (attr.is(ATTR_USER_GROUPS)) {
                addGroups = attr.getValue();

            } else if (attr.is(ATTR_CONNECTIONS)) {
                addConnections = attr.getValue();

            } else if (attr.is(ATTR_CONNECTION_GROUPS)) {
                addConnectionGroups = attr.getValue();

            } else if (attr.is(ATTR_SYSTEM_PERMISSIONS)) {
                systemPermissions = attr.getValue();

            } else {
                groupAttrs.add(attr);
            }
        }

        Uid newUid = client.createUserGroup(schema, groupAttrs);

        // Group
        associationHandler.addUserGroupsToUserGroup(newUid, addGroups);

        // Connection
        associationHandler.addConnectionsToUserGroup(newUid, addConnections);

        // ConnectionGroup
        associationHandler.addConnectionGroupsToUserGroup(newUid, addConnectionGroups);

        // Permission
        associationHandler.addSystemPermissionsToGroup(newUid, systemPermissions);

        return newUid;
    }

    /**
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    @Override
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        Set<AttributeDelta> userDelta = new HashSet<>();
        List<Object> addGroups = null;
        List<Object> removeGroups = null;
        List<Object> addConnections = null;
        List<Object> removeConnections = null;
        List<Object> addConnectionGroups = null;
        List<Object> removeConnectionGroups = null;
        List<Object> addSystemPermissions = null;
        List<Object> removeSystemPermissions = null;

        for (AttributeDelta delta : modifications) {
            if (delta.is(ATTR_USER_GROUPS)) {
                addGroups = delta.getValuesToAdd();
                removeGroups = delta.getValuesToRemove();

            } else if (delta.is(ATTR_CONNECTIONS)) {
                addConnections = delta.getValuesToAdd();
                removeConnections = delta.getValuesToRemove();

            } else if (delta.is(ATTR_CONNECTION_GROUPS)) {
                addConnectionGroups = delta.getValuesToAdd();
                removeConnectionGroups = delta.getValuesToRemove();

            } else if (delta.is(ATTR_SYSTEM_PERMISSIONS)) {
                addSystemPermissions = delta.getValuesToAdd();
                removeSystemPermissions = delta.getValuesToRemove();

            } else {
                userDelta.add(delta);
            }
        }

        try {
            if (!userDelta.isEmpty()) {
                client.updateUserGroup(schema, uid, userDelta, options);
            }
            // Group
            associationHandler.updateUserGroupsToUserGroup(uid, addGroups, removeGroups);

            // Connection
            associationHandler.updateConnectionsToUserGroup(uid, addConnections, removeConnections);

            // ConnectionGroup
            associationHandler.updateConnectionGroupsToUserGroup(uid, addConnectionGroups, removeConnectionGroups);

            // Permission
            associationHandler.updateSystemPermissionsToGroup(uid, addSystemPermissions, removeSystemPermissions);

        } catch (UnknownUidException e) {
            LOGGER.warn("Not found userGroup when updating. uid: {0}", uid);
            throw e;
        }

        return null;
    }

    /**
     * @param uid
     * @param options
     */
    @Override
    public void delete(Uid uid, OperationOptions options) {
        try {
            client.deleteUserGroup(schema, uid, options);

        } catch (UnknownUidException e) {
            LOGGER.warn("Not found userGroup when deleting. uid: {0}", uid);
            throw e;
        }
    }

    /**
     * @param filter
     * @param resultsHandler
     * @param options
     */
    @Override
    public void query(GuacamoleFilter filter, ResultsHandler resultsHandler, OperationOptions options) {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema.userGroupSchema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null && (filter.isByUid() || filter.isByName())) {
            get(filter.attributeValue, resultsHandler, options, attributesToGet, allowPartialAttributeValues);
            return;
        }

        client.getUserGroups(schema, group -> resultsHandler.handle(toConnectorObject(group, attributesToGet, allowPartialAttributeValues)), options, attributesToGet, -1);
    }


    private void get(String groupName, ResultsHandler resultsHandler, OperationOptions options, Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        GuacamoleClient.GuacamoleUserGroupRepresentation group = client.getUserGroup(schema, new Uid(groupName), options, attributesToGet);

        if (group != null) {
            resultsHandler.handle(toConnectorObject(group, attributesToGet, allowPartialAttributeValues));
        }
    }

    private ConnectorObject toConnectorObject(GuacamoleClient.GuacamoleUserGroupRepresentation group,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues) {

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(USER_GROUP_OBJECT_CLASS)
                // Need to set __UID__ and __NAME__ because it throws IllegalArgumentException
                .setUid(group.identifier)
                .setName(group.identifier);

        // Metadata
        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(group.isEnabled()));
        }

        for (GuacamoleAttribute a : group.toGuacamoleAttributes()) {
            AttributeInfo attributeInfo = schema.userGroupSchema.get(a.name);
            if (attributeInfo == null || a.value == null) {
                continue;
            }
            if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                builder.addAttribute(toConnectorAttribute(attributeInfo, a));
            }
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching associations
            LOGGER.ok("Suppress fetching associations because return partial attribute values is requested");

            Stream.of(ATTR_USERS, ATTR_CONNECTIONS, ATTR_CONNECTION_GROUPS, ATTR_USER_GROUPS).forEach(attrName -> {
                AttributeBuilder ab = new AttributeBuilder();
                ab.setName(attrName).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
                ab.addValue(Collections.EMPTY_LIST);
                builder.addAttribute(ab.build());
            });

        } else {
            if (attributesToGet == null) {
                // Suppress fetching associations default
                LOGGER.ok("Suppress fetching associations because returned by default is true");

            } else {
                if (shouldReturn(attributesToGet, ATTR_USERS)) {
                    // Fetch users
                    LOGGER.ok("Fetching users because attributes to get is requested");

                    List<String> users = associationHandler.getUsersForUserGroup(group.identifier);
                    builder.addAttribute(ATTR_USERS, users);
                }
                if (shouldReturn(attributesToGet, ATTR_USER_GROUPS)) {
                    // Fetch groups
                    LOGGER.ok("Fetching userGroups because attributes to get is requested");

                    List<String> groups = associationHandler.getUserGroupsForUserGroup(group.identifier);
                    builder.addAttribute(ATTR_USER_GROUPS, groups);
                }
                if (shouldReturn(attributesToGet, ATTR_SYSTEM_PERMISSIONS)
                        || shouldReturn(attributesToGet, ATTR_CONNECTIONS)
                        || shouldReturn(attributesToGet, ATTR_CONNECTION_GROUPS)) {
                    // Fetch all permissions
                    LOGGER.ok("Fetching permissions because attributes to get is requested");

                    GuacamoleClient.GuacamolePermissionRepresentation permissions = client.getPermissionsForUserGroup(group.identifier);

                    if (shouldReturn(attributesToGet, ATTR_SYSTEM_PERMISSIONS)) {
                        List<String> systemPermissions = permissions.systemPermissions;
                        if (systemPermissions != null) {
                            builder.addAttribute(ATTR_SYSTEM_PERMISSIONS, systemPermissions);
                        }
                    }
                    if (shouldReturn(attributesToGet, ATTR_CONNECTIONS)) {
                        // Collect connection identifiers having "READ" permission
                        List<String> connections = permissions.connectionPermissions.entrySet().stream()
                                .filter(p -> p.getValue().contains("READ"))
                                .map(p -> p.getKey())
                                .collect(Collectors.toList());
                        if (connections != null) {
                            builder.addAttribute(ATTR_CONNECTIONS, connections);
                        }
                    }
                    if (shouldReturn(attributesToGet, ATTR_CONNECTION_GROUPS)) {
                        // Collect connectionGroup identifiers having "READ" permission
                        List<String> connectionGroups = permissions.connectionGroupPermissions.entrySet().stream()
                                .filter(p -> p.getValue().contains("READ"))
                                .map(p -> p.getKey())
                                .collect(Collectors.toList());
                        if (connectionGroups != null) {
                            builder.addAttribute(ATTR_CONNECTION_GROUPS, connectionGroups);
                        }
                    }
                }
            }
        }

        return builder.build();
    }
}
