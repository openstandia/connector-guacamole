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
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;

import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static jp.openstandia.connector.guacamole.GuacamoleUtils.*;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;

public class GuacamoleUserHandler implements GuacamoleObjectHandler {

    public static final ObjectClass USER_OBJECT_CLASS = new ObjectClass("User");

    private static final Log LOGGER = Log.getLog(GuacamoleUserHandler.class);

    // The username for the user. Must be unique within the guacamole server and unchangeable.
    // Also, it's case-sensitive
    static final String ATTR_USERNAME = "username";

    // Attributes
    // Don't define here since guacamole provides user's schema endpoint

    // Permissions
    private static final String ATTR_USER_PERMISSIONS = "userPermissions";
    private static final String ATTR_SYSTEM_PERMISSIONS = "systemPermissions";

    // Activation
    static final String ATTR_DISABLED = "disabled";

    // Association
    private static final String ATTR_USER_GROUPS = "userGroups";
    private static final String ATTR_CONNECTIONS = "connections";
    private static final String ATTR_CONNECTION_GROUPS = "connectionGroups";

    private final GuacamoleConfiguration configuration;
    private final GuacamoleClient client;
    private final GuacamoleAssociationHandler associationHandler;
    private final GuacamoleSchema schema;

    public GuacamoleUserHandler(GuacamoleConfiguration configuration, GuacamoleClient client,
                                GuacamoleSchema schema) {
        this.configuration = configuration;
        this.client = client;
        this.schema = schema;
        this.associationHandler = new GuacamoleAssociationHandler(configuration, client);
    }

    public static ObjectClassInfo createSchema(List<GuacamoleClient.GuacamoleSchemaRepresentation> schema) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(USER_OBJECT_CLASS.getObjectClassValue());

        // __UID__ and __NAME__ are the same
        // username (__UID__)
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Uid.NAME)
                        .setRequired(false)
                        .setCreateable(false)
                        .setUpdateable(false)
                        .setNativeName(ATTR_USERNAME)
                        .build()
        );
        // username (__NAME__)
        AttributeInfoBuilder usernameBuilder = AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setUpdateable(false)
                .setNativeName(ATTR_USERNAME);
        builder.addAttributeInfo(usernameBuilder.build());

        // __ENABLE__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

        // __PASSWORD__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);

        // Other attributes
        // Generate from fetched guacamole schema
        schema.forEach(s -> {
            s.fields.stream()
                    .filter(f -> !(s.name.equals("restrictions") && f.name.equals(ATTR_DISABLED)))
                    .forEach(f -> {
                        switch (f.type) {
                            case "NUMERIC":
                                builder.addAttributeInfo(
                                        AttributeInfoBuilder.define(f.name)
                                                .setRequired(false) // Must be optional
                                                .setCreateable(true)
                                                .setUpdateable(true)
                                                .setType(Integer.class) // Guacamole NumericFiled is defined with Integer
                                                .build());
                                break;
                            case "BOOLEAN":
                                builder.addAttributeInfo(
                                        AttributeInfoBuilder.define(f.name)
                                                .setRequired(false) // Must be optional
                                                .setCreateable(true)
                                                .setUpdateable(true)
                                                .setType(Boolean.class)
                                                .build());
                                break;
                            case "DATE":
                                builder.addAttributeInfo(
                                        AttributeInfoBuilder.define(f.name)
                                                .setRequired(false) // Must be optional
                                                .setCreateable(true)
                                                .setUpdateable(true)
                                                .setType(ZonedDateTime.class)
                                                .build());
                                break;
                            case "PASSWORD":
                                builder.addAttributeInfo(
                                        AttributeInfoBuilder.define(f.name)
                                                .setRequired(false) // Must be optional
                                                .setCreateable(true)
                                                .setUpdateable(true)
                                                .setType(GuardedString.class)
                                                .build());
                                break;
                            case "TEXT":
                            case "EMAIL":
                            case "TIMEZONE":
                            case "TIME":
                            default: // Define Other types as string
                                builder.addAttributeInfo(
                                        AttributeInfoBuilder.define(f.name)
                                                .setRequired(false) // Must be optional
                                                .setCreateable(true)
                                                .setUpdateable(true)
                                                .build());
                                break;
                        }
                    });
        });

        // Permissions
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_USER_PERMISSIONS)
                        .setRequired(false) // Must be optional
                        .setCreateable(true)
                        .setUpdateable(true)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build()
        );
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_SYSTEM_PERMISSIONS)
                        .setRequired(false) // Must be optional
                        .setCreateable(true)
                        .setUpdateable(true)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build()
        );

        // Associations
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_USER_GROUPS)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build()
        );
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_CONNECTIONS)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build()
        );
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_CONNECTION_GROUPS)
                        .setMultiValued(true)
                        .setReturnedByDefault(false)
                        .build()
        );

        ObjectClassInfo userSchemaInfo = builder.build();

        LOGGER.ok("The constructed User core schema: {0}", userSchemaInfo);

        return userSchemaInfo;
    }

    /**
     * @param attributes
     * @return
     */
    @Override
    public Uid create(Set<Attribute> attributes) {
        Set<Attribute> userAttrs = new HashSet<>();
        List<Object> addGroups = null;
        List<Object> addConnections = null;
        List<Object> addConnectionGroups = null;
        List<Object> addUserPermissions = null;
        List<Object> addSystemPermissions = null;

        for (Attribute attr : attributes) {
            if (attr.is(ATTR_USER_GROUPS)) {
                addGroups = attr.getValue();

            } else if (attr.is(ATTR_CONNECTIONS)) {
                addConnections = attr.getValue();

            } else if (attr.is(ATTR_CONNECTION_GROUPS)) {
                addConnectionGroups = attr.getValue();

            } else if (attr.is(ATTR_USER_PERMISSIONS)) {
                addUserPermissions = attr.getValue();

            } else if (attr.is(ATTR_SYSTEM_PERMISSIONS)) {
                addSystemPermissions = attr.getValue();

            } else {
                userAttrs.add(attr);
            }
        }

        Uid newUid = client.createUser(schema, userAttrs);

        // Group
        associationHandler.addUserGroupsToUser(newUid, addGroups);

        // Connection
        associationHandler.addConnectionsToUser(newUid, addConnections);

        // ConnectionGroup
        associationHandler.addConnectionGroupsToUser(newUid, addConnectionGroups);

        // Permission
        associationHandler.addUserPermissionsToUser(newUid, addUserPermissions);
        associationHandler.addSystemPermissionsToUser(newUid, addSystemPermissions);

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
        List<Object> addUserPermissions = null;
        List<Object> removeUserPermissions = null;
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

            } else if (delta.is(ATTR_USER_PERMISSIONS)) {
                addUserPermissions = delta.getValuesToAdd();
                removeUserPermissions = delta.getValuesToRemove();

            } else if (delta.is(ATTR_SYSTEM_PERMISSIONS)) {
                addSystemPermissions = delta.getValuesToAdd();
                removeSystemPermissions = delta.getValuesToRemove();

            } else {
                userDelta.add(delta);
            }
        }

        try {
            if (!userDelta.isEmpty()) {
                client.updateUser(schema, uid, userDelta, options);
            }
            // Group
            associationHandler.updateUserGroupsToUser(uid, addGroups, removeGroups);

            // Connection
            associationHandler.updateConnectionsToUser(uid, addConnections, removeConnections);

            // ConnectionGroup
            associationHandler.updateConnectionGroupsToUser(uid, addConnectionGroups, removeConnectionGroups);

            // Permission
            associationHandler.updateUserPermissionsToUser(uid, addUserPermissions, removeUserPermissions);
            associationHandler.updateSystemPermissionsToUser(uid, addSystemPermissions, removeSystemPermissions);

        } catch (UnknownUidException e) {
            LOGGER.warn("Not found user when updating. uid: {0}", uid);
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
            client.deleteUser(schema, uid, options);

        } catch (UnknownUidException e) {
            LOGGER.warn("Not found user when deleting. uid: {0}", uid);
            throw e;
        }
    }

    @Override
    public void query(GuacamoleFilter filter, ResultsHandler resultsHandler, OperationOptions options) {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema.userSchema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null && (filter.isByUid() || filter.isByName())) {
            get(filter.attributeValue, resultsHandler, options, attributesToGet, allowPartialAttributeValues);
            return;
        }

        client.getUsers(schema,
                (user) -> resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues)),
                options, attributesToGet, -1);
    }


    private void get(String username, ResultsHandler resultsHandler, OperationOptions options, Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        GuacamoleClient.GuacamoleUserRepresentation user = client.getUser(schema, new Uid(username), options,
                attributesToGet);

        if (user != null) {
            resultsHandler.handle(toConnectorObject(user, attributesToGet, allowPartialAttributeValues));
        }
    }

    private ConnectorObject toConnectorObject(GuacamoleClient.GuacamoleUserRepresentation user,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues) {

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(USER_OBJECT_CLASS)
                // Need to set __NAME__ because it throws IllegalArgumentException
                .setUid(user.username)
                .setName(user.username);

        // Metadata
        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(user.isEnabled()));
        }

        for (GuacamoleAttribute a : user.toGuacamoleAttributes()) {
            AttributeInfo attributeInfo = schema.userSchema.get(a.name);
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

            Stream.of(ATTR_USER_GROUPS, ATTR_CONNECTIONS, ATTR_USER_PERMISSIONS, ATTR_SYSTEM_PERMISSIONS).forEach(attrName -> {
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
                if (shouldReturn(attributesToGet, ATTR_USER_GROUPS)) {
                    // Fetch userGroups
                    LOGGER.ok("Fetching userGroups because attributes to get is requested");

                    List<String> groups = associationHandler.getUserGroupsForUser(user.username);
                    builder.addAttribute(ATTR_USER_GROUPS, groups);
                }
                if (shouldReturn(attributesToGet, ATTR_USER_PERMISSIONS)
                        || shouldReturn(attributesToGet, ATTR_SYSTEM_PERMISSIONS)
                        || shouldReturn(attributesToGet, ATTR_CONNECTIONS)
                        || shouldReturn(attributesToGet, ATTR_CONNECTION_GROUPS)) {
                    // Fetch all permissions
                    LOGGER.ok("Fetching permissions because attributes to get is requested");

                    GuacamoleClient.GuacamolePermissionRepresentation permissions = client.getPermissionsForUser(user.username);

                    if (shouldReturn(attributesToGet, ATTR_USER_PERMISSIONS)) {
                        List<String> userPermissions = permissions.userPermissions.get(user.username);
                        if (userPermissions != null) {
                            List<String> filteredUserPermissions = userPermissions.stream().filter(p -> !p.equals("READ")).collect(Collectors.toList());
                            builder.addAttribute(ATTR_USER_PERMISSIONS, filteredUserPermissions);
                        }
                    }
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
                        List<String> connections = permissions.connectionGroupPermissions.entrySet().stream()
                                .filter(p -> p.getValue().contains("READ"))
                                .map(p -> p.getKey())
                                .collect(Collectors.toList());
                        if (connections != null) {
                            builder.addAttribute(ATTR_CONNECTION_GROUPS, connections);
                        }
                    }
                }
            }
        }

        return builder.build();
    }
}
