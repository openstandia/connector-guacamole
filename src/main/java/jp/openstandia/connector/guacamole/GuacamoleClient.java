package jp.openstandia.connector.guacamole;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static jp.openstandia.connector.guacamole.GuacamoleConnectionHandler.ATTR_PARAMETERS;
import static jp.openstandia.connector.guacamole.GuacamoleConnectionHandler.ATTR_PROTOCOL;
import static jp.openstandia.connector.guacamole.GuacamoleUserGroupHandler.USER_GROUP_OBJECT_CLASS;
import static jp.openstandia.connector.guacamole.GuacamoleUserHandler.ATTR_DISABLED;
import static jp.openstandia.connector.guacamole.GuacamoleUserHandler.USER_OBJECT_CLASS;
import static jp.openstandia.connector.guacamole.GuacamoleUtils.toGuacamoleAttribute;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;


public interface GuacamoleClient {
    void test();

    boolean auth();

    String getAuthToken();

    List<GuacamoleSchemaRepresentation> schema();


    default String getSchemaEndpointURL(GuacamoleConfiguration configuration) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/schema/userAttributes", url, configuration.getGuacamoleDataSource());
    }

    default String getUserEndpointURL(GuacamoleConfiguration configuration) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/users", url, configuration.getGuacamoleDataSource());
    }

    default String getUserEndpointURL(GuacamoleConfiguration configuration, Uid userUid) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/users/%s", url, configuration.getGuacamoleDataSource(), userUid.getUidValue());
    }

    default String getUserGroupsEndpointURL(GuacamoleConfiguration configuration, String username) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/users/%s/userGroups", url, configuration.getGuacamoleDataSource(), username);
    }

    default String getUserGroupEndpointURL(GuacamoleConfiguration configuration) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/userGroups", url, configuration.getGuacamoleDataSource());
    }

    default String getUserGroupEndpointURL(GuacamoleConfiguration configuration, Uid groupUid) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/userGroups/%s", url, configuration.getGuacamoleDataSource(), groupUid.getUidValue());
    }

    default String getUserGroupMembersEndpointURL(GuacamoleConfiguration configuration, String groupName) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/userGroups/%s/memberUsers", url, configuration.getGuacamoleDataSource(), groupName);
    }

    default String getUserGroupGroupsEndpointURL(GuacamoleConfiguration configuration, String groupName) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/userGroups/%s/userGroups", url, configuration.getGuacamoleDataSource(), groupName);
    }

    default String getUserPermissionEndpointURL(GuacamoleConfiguration configuration, String username) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/users/%s/permissions", url, configuration.getGuacamoleDataSource(), username);
    }

    default String getUserGroupPermissionEndpointURL(GuacamoleConfiguration configuration, String groupName) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/userGroups/%s/permissions", url, configuration.getGuacamoleDataSource(), groupName);
    }

    default String getConnectionEndpointURL(GuacamoleConfiguration configuration) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/connections", url, configuration.getGuacamoleDataSource());
    }

    default String getConnectionEndpointURL(GuacamoleConfiguration configuration, Uid connectionUid) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/connections/%s", url, configuration.getGuacamoleDataSource(), connectionUid.getUidValue());
    }

    default String getParametersEndpointURL(GuacamoleConfiguration configuration, String identifier) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/connections/%s/parameters", url, configuration.getGuacamoleDataSource(), identifier);
    }

    default String getConnectionGroupEndpointURL(GuacamoleConfiguration configuration) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/connectionGroups", url, configuration.getGuacamoleDataSource());
    }

    default String getConnectionGroupEndpointURL(GuacamoleConfiguration configuration, Uid connectionGroupUid) {
        String url = configuration.getGuacamoleURL();
        return String.format("%ssession/data/%s/connectionGroups/%s", url, configuration.getGuacamoleDataSource(), connectionGroupUid.getUidValue());
    }


    default GuacamoleUserRepresentation createGuacamoleUser(GuacamoleSchema schema, Set<Attribute> attributes) {
        GuacamoleUserRepresentation user = new GuacamoleUserRepresentation();

        for (Attribute attr : attributes) {
            // Need to get the value from __NAME__ (not __UID__)
            if (attr.getName().equals(Name.NAME)) {
                user.applyUsername(attr);

            } else if (attr.getName().equals(ENABLE_NAME)) {
                user.applyEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                user.applyPassword(AttributeUtil.getGuardedStringValue(attr));

            } else {
                if (!schema.isUserSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Guacamole doesn't support to set '%s' attribute of %s",
                            attr.getName(), USER_OBJECT_CLASS.getObjectClassValue()));
                }
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.userSchema, attr);
                user.applyAttribute(guacaAttr);
            }
        }

        // Generate username if IDM doesn't have mapping to username
        if (user.username == null) {
            user.username = UUID.randomUUID().toString();
        }

        return user;
    }

    default GuacamoleUserGroupRepresentation createGuacamoleUserGroup(GuacamoleSchema schema, Set<Attribute> attributes) {
        GuacamoleUserGroupRepresentation group = new GuacamoleUserGroupRepresentation();

        for (Attribute attr : attributes) {
            // Need to get the value from __NAME__ (not __UID__)
            if (attr.getName().equals(Name.NAME)) {
                group.applyIdentifier(attr);

            } else if (attr.getName().equals(ENABLE_NAME)) {
                group.applyEnabled(AttributeUtil.getBooleanValue(attr));

            } else {
                if (!schema.isUserGroupSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Guacamole doesn't support to set '%s' attribute of %s",
                            attr.getName(), USER_GROUP_OBJECT_CLASS.getObjectClassValue()));
                }
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.userGroupSchema, attr);
                group.applyAttribute(guacaAttr);
            }
        }

        // Generate group identifier if IDM doesn't have mapping to it
        if (group.identifier == null) {
            group.identifier = UUID.randomUUID().toString();
        }

        return group;
    }

    default GuacamoleConnectionRepresentation createGuacamoleConnection(GuacamoleSchema schema, Set<Attribute> attributes) {
        GuacamoleConnectionRepresentation conn = new GuacamoleConnectionRepresentation();

        attributes.stream().forEach(attr -> conn.apply(schema, attr));

        // Set default value for required attributes if IDM doesn't pass them
        if (conn.protocol == null) {
            conn.protocol = "vnc";
        }

        return conn;
    }

    default GuacamoleConnectionGroupRepresentation createGuacamoleConnectionGroup(GuacamoleSchema schema, Set<Attribute> attributes) {
        GuacamoleConnectionGroupRepresentation conn = new GuacamoleConnectionGroupRepresentation();

        attributes.stream().forEach(attr -> conn.apply(schema, attr));

        // Set default value for required attributes if IDM doesn't pass them
        if (conn.type == null) {
            conn.type = "ORGANIZATIONAL";
        }

        return conn;
    }

    void close();

    // User

    /**
     * @param schema
     * @param createAttributes
     * @return Username of the created user. Caution! Don't include Name object in the Uid because it throws
     * SchemaException with "No definition for ConnId NAME attribute found in definition crOCD ({http://midpoint.evolveum.com/xml/ns/public/resource/instance-3}User)
     * @throws AlreadyExistsException
     */
    Uid createUser(GuacamoleSchema schema, Set<Attribute> createAttributes) throws AlreadyExistsException;

    void updateUser(GuacamoleSchema schema, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException;

    void deleteUser(GuacamoleSchema schema, Uid uid, OperationOptions options) throws UnknownUidException;

    void getUsers(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleUserRepresentation> handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

    GuacamoleUserRepresentation getUser(GuacamoleSchema schema, Uid uid, OperationOptions options, Set<String> attributesToGet);

    void getUserGroupsForUser(String username, GuacamoleQueryHandler<String> handler);

    void assignUserGroupsToUser(Uid username, List<String> addGroups, List<String> removeGroups);

    // Group

    /**
     * @param schema
     * @param createAttributes
     * @return Identifier of the created group. Caution! Don't include Name object in the Uid because it throws
     * SchemaException with "No definition for ConnId NAME attribute found in definition crOCD ({http://midpoint.evolveum.com/xml/ns/public/resource/instance-3}UserGroup)
     * @throws AlreadyExistsException
     */
    Uid createUserGroup(GuacamoleSchema schema, Set<Attribute> createAttributes) throws AlreadyExistsException;

    void updateUserGroup(GuacamoleSchema schema, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException;

    void deleteUserGroup(GuacamoleSchema schema, Uid uid, OperationOptions options) throws UnknownUidException;

    void getUserGroups(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleUserGroupRepresentation> handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

    GuacamoleUserGroupRepresentation getUserGroup(GuacamoleSchema schema, Uid uid, OperationOptions options, Set<String> attributesToGet);

    void getUsersForUserGroup(String groupName, GuacamoleQueryHandler<String> handler);

    void assignUsersToUserGroup(Uid groupName, List<String> addUsers, List<String> removeUsers);

    void getUserGroupsForUserGroup(String groupName, GuacamoleQueryHandler<String> handler);

    void assignUserGroupsToUserGroup(Uid groupName, List<String> addGroups, List<String> removeGroups);

    // Permission

    void assignUserPermissionsToUser(Uid userUid, List<String> addPermissions, List<String> removePermissions);

    void assignSystemPermissionsToUser(Uid userUid, List<String> addPermissions, List<String> removePermissions);

    void assignSystemPermissionsToUserGroup(Uid groupUid, List<String> addPermissions, List<String> removePermissions);

    GuacamolePermissionRepresentation getPermissionsForUser(String username);

    GuacamolePermissionRepresentation getPermissionsForUserGroup(String groupName);

    // Connection

    Uid createConnection(GuacamoleSchema schema, Set<Attribute> attributes);

    void updateConnection(GuacamoleSchema schema, Uid uid, Set<AttributeDelta> modifications, OperationOptions options);

    void deleteConnection(GuacamoleSchema schema, Uid uid, OperationOptions options);

    void getConnections(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleConnectionRepresentation> handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

    GuacamoleConnectionRepresentation getConnection(GuacamoleSchema schema, Uid uid, OperationOptions options, Set<String> attributesToGet);

    GuacamoleConnectionRepresentation getConnection(GuacamoleSchema schema, Name name, OperationOptions options, Set<String> attributesToGet);

    Map<String, String> getParameters(String identifier);

    void assignConnectionsToUser(Uid userUid, List<String> addConnections, List<String> removeConnections);

    void assignConnectionsToUserGroup(Uid userGroupUid, List<String> addConnections, List<String> removeConnections);

    // ConnectionGroup

    Uid createConnectionGroup(GuacamoleSchema schema, Set<Attribute> attributes);

    void updateConnectionGroup(GuacamoleSchema schema, Uid uid, Set<AttributeDelta> modifications, OperationOptions options);

    void deleteConnectionGroup(GuacamoleSchema schema, Uid uid, OperationOptions options);

    void getConnectionGroups(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleConnectionGroupRepresentation> handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

    GuacamoleConnectionGroupRepresentation getConnectionGroup(GuacamoleSchema schema, Uid uid, OperationOptions options, Set<String> attributesToGet);

    GuacamoleConnectionGroupRepresentation getConnectionGroup(GuacamoleSchema schema, Name name, OperationOptions options, Set<String> attributesToGet);

    void assignConnectionGroupsToUser(Uid userUid, List<String> addConnectionGroups, List<String> removeConnectionGroups);

    void assignConnectionGroupsToUserGroup(Uid userGroupUid, List<String> addConnectionGroups, List<String> removeConnectionGroups);


    // JSON Representation

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamoleUserRepresentation {
        public String username;
        public GuardedString password;
        public Map<String, String> attributes = new HashMap<>();

        public void applyUsername(Attribute attr) {
            this.username = AttributeUtil.getAsStringValue(attr);
        }

        public void applyEnabled(Boolean enable) {
            if (Boolean.FALSE.equals(enable)) {
                attributes.put(ATTR_DISABLED, "true");
            } else {
                attributes.put(ATTR_DISABLED, "");
            }
        }

        public void applyPassword(GuardedString password) {
            this.password = password;
        }

        public String getPassword() {
            if (password == null) {
                return null;
            }
            AtomicReference<String> rawPassword = new AtomicReference<>();
            this.password.access((c) -> rawPassword.set(String.valueOf(c)));
            return rawPassword.get();
        }

        public void applyAttribute(GuacamoleAttribute attr) {
            this.attributes.put(attr.name, attr.value);
        }

        @JsonIgnore
        public boolean isEnabled() {
            String disabled = attributes.get(ATTR_DISABLED);
            return !"true".equals(disabled);
        }

        public List<GuacamoleAttribute> toGuacamoleAttributes() {
            return attributes.entrySet().stream().map(a -> new GuacamoleAttribute(a.getKey(), a.getValue())).collect(Collectors.toList());
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamoleSchemaRepresentation {
        public String name;
        public List<GuacamoleSchemaFieldRepresentation> fields;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamoleSchemaFieldRepresentation {
        public String name;
        public String type;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamoleUserGroupRepresentation {
        public String identifier;
        public Map<String, String> attributes = new HashMap<>();

        public void applyIdentifier(Attribute attr) {
            this.identifier = AttributeUtil.getAsStringValue(attr);
        }

        public void applyEnabled(Boolean enable) {
            if (Boolean.FALSE.equals(enable)) {
                attributes.put(ATTR_DISABLED, "true");
            } else {
                attributes.put(ATTR_DISABLED, "");
            }
        }

        public void applyAttribute(GuacamoleAttribute attr) {
            this.attributes.put(attr.name, attr.value);
        }

        @JsonIgnore
        public boolean isEnabled() {
            String disabled = attributes.get(ATTR_DISABLED);
            return !"true".equals(disabled);
        }

        public List<GuacamoleAttribute> toGuacamoleAttributes() {
            return attributes.entrySet().stream().map(a -> new GuacamoleAttribute(a.getKey(), a.getValue())).collect(Collectors.toList());
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamoleErrorRepresentation {
        public String message;
        public String type;

        public boolean isAlreadyExists() {
            return type.equals("BAD_REQUEST") && message.endsWith("already exists.");
        }

        public boolean isUnauthorized() {
            return type.equals("PERMISSION_DENIED");
        }

        public boolean isBlankUsername() {
            return type.equals("BAD_REQUEST") && message.endsWith("The username must not be blank.");
        }
    }

    class PatchOperation {
        final public String op;
        final public String path;
        final public String value;

        public PatchOperation(String op, String path, String value) {
            this.op = op;
            this.path = path;
            this.value = value;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamolePermissionRepresentation {
        public Map<String, List<String>> connectionGroupPermissions;
        public Map<String, List<String>> connectionPermissions;
        public List<String> systemPermissions;
        public Map<String, List<String>> userPermissions;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamoleConnectionRepresentation {
        public String identifier;
        public String name;
        public String parentIdentifier;
        public String protocol;
        public Map<String, String> attributes = new HashMap<>();
        public Map<String, String> parameters = new HashMap<>();

        public void apply(GuacamoleSchema schema, Attribute attr) {
            if (attr.is(Name.NAME)) {
                applyParentIdentifierAndName(AttributeUtil.getStringValue(attr));

            } else if (attr.is(ATTR_PROTOCOL)) {
                applyProtocol(AttributeUtil.getStringValue(attr));

            } else if (attr.is(ATTR_PARAMETERS)) {
                applyParameters(attr.getValue(), false);

            } else {
                if (!schema.isConnectionSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Guacamole doesn't support to set '%s' attribute of Connection",
                            attr.getName()));
                }
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.connectionSchema, attr);
                applyAttribute(guacaAttr);
            }
        }

        public void applyDelta(GuacamoleSchema schema, AttributeDelta delta) {
            if (delta.is(Name.NAME)) {
                applyParentIdentifierAndName(AttributeDeltaUtil.getStringValue(delta));

            } else if (delta.is(ATTR_PROTOCOL)) {
                applyProtocol(AttributeDeltaUtil.getStringValue(delta));

            } else if (delta.is(ATTR_PARAMETERS)) {
                // We need to apply "ValuesToRemove" first because of replace situation
                applyParameters(delta.getValuesToRemove(), true);
                applyParameters(delta.getValuesToAdd(), false);

            } else {
                if (!schema.isConnectionSchema(delta)) {
                    throw new InvalidAttributeValueException(String.format("Guacamole doesn't support to set '%s' attribute of Connection",
                            delta.getName()));
                }
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.connectionSchema, delta);
                applyAttribute(guacaAttr);
            }
        }

        private void applyParentIdentifierAndName(String s) {
            if (!s.contains("/")) {
                throw new InvalidAttributeValueException("Invalid name-with-parentIdentifier. The format must be <parentIdentifier>/<name>. value: " + s);
            }
            String parentIdentifier = s.substring(0, s.indexOf("/"));
            String name = s.substring(s.indexOf("/"));

            if (name.length() == 1) {
                throw new InvalidAttributeValueException("Invalid name-with-parentIdentifier. The format must be <parentIdentifier>/<name>. value: " + s);
            }
            name = name.substring(1);

            this.parentIdentifier = parentIdentifier;
            this.name = name;
        }

        private void applyProtocol(String protocol) {
            this.protocol = protocol;
        }

        private void applyAttribute(GuacamoleAttribute attr) {
            this.attributes.put(attr.name, attr.value);
        }

        private void applyParameters(List<Object> values, boolean delete) {
            if (values == null) {
                return;
            }
            for (Object o : values) {
                if (!(o instanceof String) || !(((String) o).contains("="))) {
                    throw new InvalidAttributeValueException("Invalid parameter. It must be 'key=value' string format. value: " + o);
                }
                String kv = (String) o;
                String key = kv.substring(0, kv.indexOf('='));
                String value = kv.substring(kv.indexOf('='));

                if (delete) {
                    parameters.remove(key);
                    continue;
                }

                if (value.length() > 1) {
                    parameters.put(key, value.substring(1));
                } else {
                    parameters.put(key, null);
                }
            }
        }

        public List<GuacamoleAttribute> toGuacamoleAttributes() {
            return attributes.entrySet().stream().map(a -> new GuacamoleAttribute(a.getKey(), a.getValue())).collect(Collectors.toList());
        }

        public List<GuacamoleAttribute> toParameters() {
            return parameters.entrySet().stream().map(a -> new GuacamoleAttribute(a.getKey(), a.getValue())).collect(Collectors.toList());
        }

        public String toUniqueName() {
            // Add parentIdentifier as prefix to make it unique
            return parentIdentifier + "/" + name;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    class GuacamoleConnectionGroupRepresentation {
        public String identifier;
        public String name;
        public String parentIdentifier;
        public String type;
        public Map<String, String> attributes = new HashMap<>();

        public void apply(GuacamoleSchema schema, Attribute attr) {
            if (attr.is(Name.NAME)) {
                applyParentIdentifierAndName(AttributeUtil.getStringValue(attr));

            } else {
                if (!schema.isConnectionSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Guacamole doesn't support to set '%s' attribute of ConnectionGroup",
                            attr.getName()));
                }
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.connectionGroupSchema, attr);
                applyAttribute(guacaAttr);
            }
        }

        public void applyDelta(GuacamoleSchema schema, AttributeDelta delta) {
            if (delta.is(Name.NAME)) {
                applyParentIdentifierAndName(AttributeDeltaUtil.getStringValue(delta));

            } else {
                if (!schema.isConnectionSchema(delta)) {
                    throw new InvalidAttributeValueException(String.format("Guacamole doesn't support to set '%s' attribute of ConnectionGroup",
                            delta.getName()));
                }
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.connectionGroupSchema, delta);
                applyAttribute(guacaAttr);
            }
        }

        private void applyParentIdentifierAndName(String s) {
            if (!s.contains("/")) {
                throw new InvalidAttributeValueException("Invalid name-with-parentIdentifier. The format must be <parentIdentifier>/<name>. value: " + s);
            }
            String parentIdentifier = s.substring(0, s.indexOf("/"));
            String name = s.substring(s.indexOf("/"));

            if (name.length() == 1) {
                throw new InvalidAttributeValueException("Invalid name-with-parentIdentifier. The format must be <parentIdentifier>/<name>. value: " + s);
            }
            name = name.substring(1);

            this.parentIdentifier = parentIdentifier;
            this.name = name;
        }

        private void applyName(String name) {
            this.name = name;
        }

        private void applyAttribute(GuacamoleAttribute attr) {
            this.attributes.put(attr.name, attr.value);
        }

        public List<GuacamoleAttribute> toGuacamoleAttributes() {
            return attributes.entrySet().stream().map(a -> new GuacamoleAttribute(a.getKey(), a.getValue())).collect(Collectors.toList());
        }

        public String toUniqueName() {
            // Add parentIdentifier as prefix to make it unique
            return parentIdentifier + "/" + name;
        }
    }
}