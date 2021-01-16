package jp.openstandia.connector.guacamole.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jp.openstandia.connector.guacamole.*;
import okhttp3.*;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.*;
import org.identityconnectors.framework.common.objects.*;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static jp.openstandia.connector.guacamole.GuacamoleConnectionGroupHandler.CONNECTION_GROUP_OBJECT_CLASS;
import static jp.openstandia.connector.guacamole.GuacamoleConnectionHandler.CONNECTION_OBJECT_CLASS;
import static jp.openstandia.connector.guacamole.GuacamoleUserGroupHandler.USER_GROUP_OBJECT_CLASS;
import static jp.openstandia.connector.guacamole.GuacamoleUserHandler.USER_OBJECT_CLASS;
import static jp.openstandia.connector.guacamole.GuacamoleUtils.toGuacamoleAttribute;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.PASSWORD_NAME;

public class GuacamoleRESTClient implements GuacamoleClient {

    private static final Log LOG = Log.getLog(GuacamoleRESTClient.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String instanceName;
    private final GuacamoleConfiguration configuration;
    private final OkHttpClient httpClient;

    private String authToken;

    public GuacamoleRESTClient(String instanceName, GuacamoleConfiguration configuration, OkHttpClient httpClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.httpClient = httpClient;
    }

    @Override
    public void test() {
        auth();
    }

    @Override
    public boolean auth() {
        FormBody.Builder formBuilder = new FormBody.Builder()
                .add("username", configuration.getApiUsername());

        configuration.getApiPassword().access((password) -> {
            formBuilder.add("password", String.valueOf(password));
        });

        Request request = new Request.Builder()
                .url(configuration.getGuacamoleURL() + "tokens")
                .post(formBuilder.build())
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (response.code() == 403) {
                throw new ConnectionFailedException("Unauthorized");
            }
            if (response.code() != 200) {
                // Something wrong..
                String body = response.body().string();
                throw new ConnectionFailedException(String.format("Unexpected authentication response. statusCode: %s, body: %s",
                        response.code(),
                        body));
            }

            Map<String, String> resJson = MAPPER.readValue(response.body().byteStream(), Map.class);
            this.authToken = resJson.get("authToken");
            String username = resJson.get("username");

            if (this.authToken == null) {
                // Something wrong...
                throw new ConnectionFailedException("Cannot get auth token");
            }

            LOG.info("[{0}] Guacamole connector authenticated by {1}", instanceName, username);

            return true;

        } catch (IOException e) {
            throw new ConnectionFailedException("Cannot connect to the guacamole server", e);
        }
    }

    @Override
    public String getAuthToken() {
        return authToken;
    }

    @Override
    public void close() {
    }

    @Override
    public Uid createUser(GuacamoleSchema schema, Set<Attribute> createAttributes) throws AlreadyExistsException {
        GuacamoleClient.GuacamoleUserRepresentation user = createGuacamoleUser(schema, createAttributes);

        try (Response response = post(getUserEndpointURL(configuration), user)) {
            if (response.code() == 400) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isAlreadyExists()) {
                    throw new AlreadyExistsException(String.format("User '%s' already exists.", user.username));
                }
                throw new InvalidAttributeValueException(String.format("Bad request when creating a user. username: %s", user.username));
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to create guacamole user: %s, statusCode: %d", user.username, response.code()));
            }

            // Created
            return new Uid(user.username);

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole create user API", e);
        }
    }

    @Override
    public void updateUser(GuacamoleSchema schema, Uid userUid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        // Need to fetch the target user first to update because we need to send all attributes including unmodified attributes
        GuacamoleUserRepresentation target = getUser(schema, userUid, options, null);
        if (target == null) {
            throw new UnknownUidException(userUid, USER_OBJECT_CLASS);
        }

        // Apply delta
        modifications.stream().forEach(delta -> {
            if (delta.getName().equals(ENABLE_NAME)) {
                target.applyEnabled(AttributeDeltaUtil.getBooleanValue(delta));
            } else if (delta.getName().equals(PASSWORD_NAME)) {
                target.applyPassword(AttributeDeltaUtil.getGuardedStringValue(delta));
            } else {
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.userSchema, delta);
                target.applyAttribute(guacaAttr);
            }
        });

        callUpdate(USER_OBJECT_CLASS, getUserGroupEndpointURL(configuration, userUid), userUid, target);
    }

    @Override
    public void deleteUser(GuacamoleSchema schema, Uid userUid, OperationOptions options) throws UnknownUidException {
        callDelete(USER_OBJECT_CLASS, getUserEndpointURL(configuration, userUid), userUid);
    }

    @Override
    public void getUsers(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleUserRepresentation> handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize) {
        try (Response response = get(getUserEndpointURL(configuration))) {
            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole users. statusCode: %d", response.code()));
            }

            // Success
            Map<String, GuacamoleUserRepresentation> users = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<Map<String, GuacamoleUserRepresentation>>() {
                    });
            users.entrySet().stream().forEach(entry -> handler.handle(entry.getValue()));

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get users API", e);
        }
    }

    @Override
    public GuacamoleUserRepresentation getUser(GuacamoleSchema schema, Uid uid, OperationOptions options, Set<String> attributesToGet) {
        try (Response response = get(getUserEndpointURL(configuration, uid))) {
            if (response.code() == 404) {
                // Don't throw
                return null;
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole user. statusCode: %d", response.code()));
            }

            // Success
            GuacamoleUserRepresentation user = MAPPER.readValue(response.body().byteStream(), GuacamoleUserRepresentation.class);
            return user;

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get user API", e);
        }
    }

    @Override
    public void getUserGroupsForUser(String username, GuacamoleQueryHandler<String> handler) {
        try (Response response = get(getUserGroupsEndpointURL(configuration, username))) {
            if (response.code() == 404) {
                // Don't throw
                return;
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole groups for user: %s, statusCode: %d", username, response.code()));
            }

            // Success
            List<String> groups = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<List<String>>() {
                    });
            groups.stream().forEach(groupName -> handler.handle(groupName));

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get user groups API", e);
        }
    }

    @Override
    public void assignUserGroupsToUser(Uid userUid, List<String> addGroups, List<String> removeGroups) {
        callAssign(USER_OBJECT_CLASS, getUserGroupsEndpointURL(configuration, userUid.getUidValue()), "/",
                userUid, addGroups, removeGroups);
    }

    @Override
    public Uid createUserGroup(GuacamoleSchema schema, Set<Attribute> createAttributes) throws AlreadyExistsException {
        GuacamoleUserGroupRepresentation group = createGuacamoleUserGroup(schema, createAttributes);

        try (Response response = post(getUserGroupEndpointURL(configuration), group)) {
            if (response.code() == 400) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isAlreadyExists()) {
                    throw new AlreadyExistsException(String.format("Group '%s' already exists.", group.identifier));
                }
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to create guacamole group: %s, statusCode: %d", group.identifier, response.code()));
            }

            // Created
            return new Uid(group.identifier);

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole API", e);
        }
    }

    @Override
    public void updateUserGroup(GuacamoleSchema schema, Uid groupUid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        // Need to fetch the target group first to update because we need to send all attributes including unmodified attributes
        GuacamoleUserGroupRepresentation target = getUserGroup(schema, groupUid, options, null);
        if (target == null) {
            throw new UnknownUidException(groupUid, USER_GROUP_OBJECT_CLASS);
        }

        // Apply delta
        modifications.stream().forEach(delta -> {
            if (delta.getName().equals(ENABLE_NAME)) {
                target.applyEnabled(AttributeDeltaUtil.getBooleanValue(delta));
            } else {
                GuacamoleAttribute guacaAttr = toGuacamoleAttribute(schema.userGroupSchema, delta);
                target.applyAttribute(guacaAttr);
            }
        });

        callUpdate(USER_GROUP_OBJECT_CLASS, getUserGroupEndpointURL(configuration, groupUid), groupUid, target);
    }

    @Override
    public void deleteUserGroup(GuacamoleSchema schema, Uid groupUid, OperationOptions options) throws UnknownUidException {
        callDelete(USER_OBJECT_CLASS, getUserGroupEndpointURL(configuration, groupUid), groupUid);
    }

    @Override
    public void getUserGroups(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleUserGroupRepresentation> handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize) {
        try (Response response = get(getUserGroupEndpointURL(configuration))) {
            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole groups. statusCode: %d", response.code()));
            }

            // Success
            Map<String, GuacamoleUserGroupRepresentation> groups = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<Map<String, GuacamoleUserGroupRepresentation>>() {
                    });
            groups.entrySet().stream().forEach(entry -> handler.handle(entry.getValue()));

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get groups API", e);
        }
    }

    @Override
    public GuacamoleUserGroupRepresentation getUserGroup(GuacamoleSchema schema, Uid uid, OperationOptions options, Set<String> attributesToGet) {
        try {
            Response response = get(getUserGroupEndpointURL(configuration, uid));

            if (response.code() == 404) {
                // Don't throw
                return null;
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole group. statusCode: %d", response.code()));
            }

            // Success
            GuacamoleUserGroupRepresentation group = MAPPER.readValue(response.body().byteStream(), GuacamoleUserGroupRepresentation.class);
            return group;

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get group API", e);
        }
    }

    @Override
    public void getUsersForUserGroup(String groupName, GuacamoleQueryHandler<String> handler) {
        try {
            Response response = get(getUserGroupMembersEndpointURL(configuration, groupName));

            if (response.code() == 404) {
                // Don't throw
                return;
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole users for group: %s, statusCode: %d",
                        groupName, response.code()));
            }

            // Success
            List<String> users = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<List<String>>() {
                    });
            users.stream().forEach(username -> handler.handle(username));

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole group members API", e);
        }
    }

    @Override
    public void assignUsersToUserGroup(Uid groupUid, List<String> addUsers, List<String> removeUsers) {
        callAssign(USER_GROUP_OBJECT_CLASS, getUserGroupMembersEndpointURL(configuration, groupUid.getUidValue()), "/",
                groupUid, addUsers, removeUsers);
    }

    @Override
    public void getUserGroupsForUserGroup(String groupName, GuacamoleQueryHandler<String> handler) {
        try {
            Response response = get(getUserGroupGroupsEndpointURL(configuration, groupName));

            if (response.code() == 404) {
                // Don't throw
                return;
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole groups for group: %s, statusCode: %d",
                        groupName, response.code()));
            }

            // Success
            List<String> groups = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<List<String>>() {
                    });
            groups.stream().forEach(g -> handler.handle(g));

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole group members API", e);
        }
    }

    @Override
    public void assignUserGroupsToUserGroup(Uid groupUid, List<String> addGroups, List<String> removeGroups) {
        callAssign(USER_GROUP_OBJECT_CLASS, getUserGroupGroupsEndpointURL(configuration, groupUid.getUidValue()), "/",
                groupUid, addGroups, removeGroups);
    }

    // Permission

    @Override
    public void assignUserPermissionsToUser(Uid userUid, List<String> addPermissions, List<String> removePermissions) {
        callAssign(USER_OBJECT_CLASS, getUserPermissionEndpointURL(configuration, userUid.getUidValue()), "/userPermissions/" + userUid.getUidValue(),
                userUid, addPermissions, removePermissions);
    }

    @Override
    public void assignSystemPermissionsToUser(Uid userUid, List<String> addPermissions, List<String> removePermissions) {
        callAssign(USER_OBJECT_CLASS, getUserPermissionEndpointURL(configuration, userUid.getUidValue()), "/systemPermissions",
                userUid, addPermissions, removePermissions);
    }

    @Override
    public void assignSystemPermissionsToUserGroup(Uid groupUid, List<String> addPermissions, List<String> removePermissions) {
        callAssign(USER_GROUP_OBJECT_CLASS, getUserGroupPermissionEndpointURL(configuration, groupUid.getUidValue()), "/systemPermissions",
                groupUid, addPermissions, removePermissions);
    }

    @Override
    public GuacamolePermissionRepresentation getPermissionsForUser(String username) {
        try {
            Response response = get(getUserPermissionEndpointURL(configuration, username));

            if (response.code() == 404) {
                throw new UnknownUidException(new Uid(username), USER_OBJECT_CLASS);
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole permissions for user: %s, statusCode: %d",
                        username, response.code()));
            }

            // Success
            GuacamolePermissionRepresentation permission = MAPPER.readValue(response.body().byteStream(), GuacamolePermissionRepresentation.class);
            return permission;

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to get guacamole permissions for user: %s", username));
        }
    }

    @Override
    public GuacamolePermissionRepresentation getPermissionsForUserGroup(String groupName) {
        try {
            Response response = get(getUserGroupPermissionEndpointURL(configuration, groupName));

            if (response.code() == 404) {
                throw new UnknownUidException(new Uid(groupName), USER_GROUP_OBJECT_CLASS);
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole permissions for user: %s, statusCode: %d",
                        groupName, response.code()));
            }

            // Success
            GuacamolePermissionRepresentation permission = MAPPER.readValue(response.body().byteStream(), GuacamolePermissionRepresentation.class);
            return permission;

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to get guacamole permissions for user: %s", groupName));
        }
    }

    // Connection

    @Override
    public Uid createConnection(GuacamoleSchema schema, Set<Attribute> attributes) {
        GuacamoleClient.GuacamoleConnectionRepresentation conn = createGuacamoleConnection(schema, attributes);

        try (Response response = post(getConnectionEndpointURL(configuration), conn)) {
            if (response.code() == 400) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isAlreadyExists()) {
                    throw new AlreadyExistsException(String.format("Connection '%s' already exists.", conn.name));
                }
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to create guacamole connection: %s, statusCode: %d",
                        conn.name, response.code()));
            }

            GuacamoleConnectionRepresentation created = MAPPER.readValue(response.body().byteStream(), GuacamoleConnectionRepresentation.class);

            // Created
            return new Uid(created.identifier, new Name(created.parentIdentifier + "/" + created.name));

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to create guacamole connection: %s", conn.name));
        }
    }

    @Override
    public void updateConnection(GuacamoleSchema schema, Uid connectionUid, Set<AttributeDelta> modifications, OperationOptions options) {
        // Need to fetch the target connection first to update because we need to send all attributes including unmodified attributes
        GuacamoleConnectionRepresentation target = getConnection(schema, connectionUid, options, null);
        if (target == null) {
            throw new UnknownUidException(connectionUid, CONNECTION_OBJECT_CLASS);
        }

        Map<String, String> parameters = getConnectionParameters(schema, connectionUid);
        target.parameters = parameters;

        // Apply delta
        modifications.stream().forEach(delta -> target.applyDelta(schema, delta));

        callUpdate(CONNECTION_OBJECT_CLASS, getConnectionEndpointURL(configuration, connectionUid), connectionUid, target);
    }

    @Override
    public void deleteConnection(GuacamoleSchema schema, Uid connectionUid, OperationOptions options) {
        callDelete(CONNECTION_OBJECT_CLASS, getConnectionEndpointURL(configuration, connectionUid), connectionUid);
    }

    @Override
    public void getConnections(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleConnectionRepresentation> handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize) {
        try (Response response = get(getConnectionEndpointURL(configuration))) {
            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole connections. statusCode: %d", response.code()));
            }

            // Success
            Map<String, GuacamoleConnectionRepresentation> connections = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<Map<String, GuacamoleConnectionRepresentation>>() {
                    });
            for (Map.Entry<String, GuacamoleConnectionRepresentation> entry : connections.entrySet()) {
                if (!handler.handle(entry.getValue())) {
                    break;
                }
            }
        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get connections API", e);
        }
    }

    private Map<String, String> getConnectionParameters(GuacamoleSchema schema, Uid uid) {
        try {
            Response response = get(getParametersEndpointURL(configuration, uid.getUidValue()));

            if (response.code() == 404) {
                // Don't throw
                return Collections.emptyMap();
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole connection parameters: %s, statusCode: %d",
                        uid.getUidValue(), response.code()));
            }

            // Success
            Map<String, String> conn = MAPPER.readValue(response.body().byteStream(), Map.class);
            return conn;

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get connection parameters API", e);
        }
    }

    @Override
    public GuacamoleConnectionRepresentation getConnection(GuacamoleSchema schema, Uid uid, OperationOptions options, Set<String> attributesToGet) {
        try {
            Response response = get(getConnectionEndpointURL(configuration, uid));

            if (response.code() == 404) {
                // Don't throw
                return null;
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole connection: %s, statusCode: %d",
                        uid.getUidValue(), response.code()));
            }

            // Success
            GuacamoleConnectionRepresentation conn = MAPPER.readValue(response.body().byteStream(), GuacamoleConnectionRepresentation.class);
            return conn;

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get connection API", e);
        }
    }

    @Override
    public GuacamoleConnectionRepresentation getConnection(GuacamoleSchema schema, Name name, OperationOptions options, Set<String> attributesToGet) {
        LOG.info("getConnection by Name start (it might take a while...)");

        AtomicReference<GuacamoleConnectionRepresentation> store = new AtomicReference<>();
        // Need to fetch all connections
        // It might cause performance issue when there are a lot of connections
        getConnections(schema, conn -> {
            if (conn.toUniqueName().equals(name.getNameValue())) {
                store.set(conn);
                return false;
            }
            return true;
        }, options, attributesToGet, -1);

        LOG.info("getConnection by Name end");

        return store.get();
    }

    @Override
    public Map<String, String> getParameters(String identifier) {
        try (Response response = get(getParametersEndpointURL(configuration, identifier))) {
            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole connection parameters. connection: %s, statusCode: %d",
                        identifier, response.code()));
            }

            // Success
            Map<String, String> conns = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<Map<String, String>>() {
                    });
            return conns;

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get connection parameters API", e);
        }
    }

    @Override
    public void assignConnectionsToUser(Uid userUid, List<String> addConnections, List<String> removeConnections) {
        callAssignConnections(USER_OBJECT_CLASS, getUserPermissionEndpointURL(configuration, userUid.getUidValue()),
                "/connectionPermissions/", userUid, addConnections, removeConnections);
    }

    @Override
    public void assignConnectionsToUserGroup(Uid userGroupUid, List<String> addConnections, List<String> removeConnections) {
        callAssignConnections(USER_GROUP_OBJECT_CLASS, getUserGroupPermissionEndpointURL(configuration, userGroupUid.getUidValue()),
                "/connectionPermissions/", userGroupUid, addConnections, removeConnections);
    }

    // ConnectionGroup

    @Override
    public Uid createConnectionGroup(GuacamoleSchema schema, Set<Attribute> attributes) {
        GuacamoleClient.GuacamoleConnectionGroupRepresentation connGroup = createGuacamoleConnectionGroup(schema, attributes);

        try (Response response = post(getConnectionGroupEndpointURL(configuration), connGroup)) {
            if (response.code() == 400) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isAlreadyExists()) {
                    throw new AlreadyExistsException(String.format("ConnectionGroup '%s' already exists.", connGroup.name));
                }
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to create guacamole connectionGroup: %s, statusCode: %d",
                        connGroup.name, response.code()));
            }

            GuacamoleConnectionRepresentation created = MAPPER.readValue(response.body().byteStream(), GuacamoleConnectionRepresentation.class);

            // Created
            return new Uid(created.identifier, new Name(created.parentIdentifier + "/" + created.name));

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to create guacamole connectionGroup: %s", connGroup.name));
        }
    }

    @Override
    public void updateConnectionGroup(GuacamoleSchema schema, Uid connectionGroupUid, Set<AttributeDelta> modifications, OperationOptions options) {
        // Need to fetch the target connectionGroup first to update because we need to send all attributes including unmodified attributes
        GuacamoleConnectionGroupRepresentation target = getConnectionGroup(schema, connectionGroupUid, options, null);
        if (target == null) {
            throw new UnknownUidException(connectionGroupUid, CONNECTION_GROUP_OBJECT_CLASS);
        }

        // Apply delta
        modifications.stream().forEach(delta -> target.applyDelta(schema, delta));

        callUpdate(CONNECTION_GROUP_OBJECT_CLASS, getConnectionGroupEndpointURL(configuration, connectionGroupUid), connectionGroupUid, target);
    }

    @Override
    public void deleteConnectionGroup(GuacamoleSchema schema, Uid connectionGroupUid, OperationOptions options) {
        callDelete(CONNECTION_GROUP_OBJECT_CLASS, getConnectionGroupEndpointURL(configuration, connectionGroupUid), connectionGroupUid);
    }

    @Override
    public void getConnectionGroups(GuacamoleSchema schema, GuacamoleQueryHandler<GuacamoleConnectionGroupRepresentation> handler,
                                    OperationOptions options, Set<String> attributesToGet, int queryPageSize) {
        try (Response response = get(getConnectionGroupEndpointURL(configuration))) {
            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole connectionGroups. statusCode: %d", response.code()));
            }

            // Success
            Map<String, GuacamoleConnectionGroupRepresentation> connections = MAPPER.readValue(response.body().byteStream(),
                    new TypeReference<Map<String, GuacamoleConnectionGroupRepresentation>>() {
                    });
            for (Map.Entry<String, GuacamoleConnectionGroupRepresentation> entry : connections.entrySet()) {
                if (!handler.handle(entry.getValue())) {
                    break;
                }
            }
        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get connectionGroups API", e);
        }
    }

    @Override
    public GuacamoleConnectionGroupRepresentation getConnectionGroup(GuacamoleSchema schema, Uid connectionGroupUid,
                                                                     OperationOptions options, Set<String> attributesToGet) {
        try {
            Response response = get(getConnectionGroupEndpointURL(configuration, connectionGroupUid));

            if (response.code() == 404) {
                // Don't throw
                return null;
            }

            if (response.code() != 200) {
                throw new ConnectorIOException(String.format("Failed to get guacamole connectionGroup: %s, statusCode: %d",
                        connectionGroupUid.getUidValue(), response.code()));
            }

            // Success
            GuacamoleConnectionGroupRepresentation conn = MAPPER.readValue(response.body().byteStream(), GuacamoleConnectionGroupRepresentation.class);
            return conn;

        } catch (IOException e) {
            throw new ConnectorIOException("Failed to call guacamole get connectionGroup API", e);
        }
    }

    @Override
    public GuacamoleConnectionGroupRepresentation getConnectionGroup(GuacamoleSchema schema, Name connectionGroupName,
                                                                     OperationOptions options, Set<String> attributesToGet) {
        LOG.info("getConnectionGroup by Name start (it might take a while...)");

        AtomicReference<GuacamoleConnectionGroupRepresentation> store = new AtomicReference<>();
        // Need to fetch all connectionGroups
        // It might cause performance issue when there are a lot of connectionGroups
        getConnectionGroups(schema, connGroup -> {
            if (connGroup.toUniqueName().equals(connectionGroupName.getNameValue())) {
                store.set(connGroup);
                return false;
            }
            return true;
        }, options, attributesToGet, -1);

        LOG.info("getConnectionGroup by Name end");

        return store.get();
    }

    @Override
    public void assignConnectionGroupsToUser(Uid userUid, List<String> addConnectionGroups, List<String> removeConnectionGroups) {
        callAssignConnections(USER_OBJECT_CLASS, getUserPermissionEndpointURL(configuration, userUid.getUidValue()),
                "/connectionGroupPermissions/", userUid, addConnectionGroups, removeConnectionGroups);
    }

    @Override
    public void assignConnectionGroupsToUserGroup(Uid userGroupUid, List<String> addConnectionGroups, List<String> removeConnectionGroups) {
        callAssignConnections(USER_GROUP_OBJECT_CLASS, getUserGroupPermissionEndpointURL(configuration, userGroupUid.getUidValue()),
                "/connectionGroupPermissions/", userGroupUid, addConnectionGroups, removeConnectionGroups);
    }

    // Utilities

    protected void callUpdate(ObjectClass objectClass, String url, Uid uid, Object target) {
        try (Response response = put(url, target)) {
            if (response.code() == 400) {
                throw new InvalidAttributeValueException(String.format("Bad request when updating %s: %s, response: %s",
                        objectClass.getObjectClassValue(), uid.getUidValue(), toBody(response)));
            }

            if (response.code() == 404) {
                throw new UnknownUidException(uid, objectClass);
            }

            if (response.code() != 204) {
                throw new ConnectorIOException(String.format("Failed to update guacamole %s: %s, statusCode: %d, response: %s",
                        objectClass.getObjectClassValue(), uid.getUidValue(), response.code(), toBody(response)));
            }

            // Success

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to update guacamole %s: %s",
                    objectClass.getObjectClassValue(), uid.getUidValue()), e);
        }
    }

    private String toBody(Response response) {
        ResponseBody resBody = response.body();
        if (resBody == null) {
            return null;
        }
        try {
            return resBody.string();
        } catch (IOException e) {
            LOG.error(e, "Unexpected guacamole API response");
            return "<failed_to_parse_response>";
        }
    }

    /**
     * Generic delete method.
     *
     * @param objectClass
     * @param url
     * @param uid
     */
    protected void callDelete(ObjectClass objectClass, String url, Uid uid) {
        try (Response response = delete(url)) {
            if (response.code() == 404) {
                throw new UnknownUidException(uid, objectClass);
            }

            if (response.code() != 204) {
                throw new ConnectorIOException(String.format("Failed to delete guacamole %s: %s, statusCode: %d, response: %s",
                        objectClass.getObjectClassValue(), uid.getUidValue(), response.code(), toBody(response)));
            }

            // Success

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to delete guacamole %s: %s",
                    objectClass.getObjectClassValue(), uid.getUidValue()), e);
        }
    }

    /**
     * Generic assign method.
     *
     * @param objectClass
     * @param url
     * @param path
     * @param uid
     * @param add
     * @param remove
     */
    protected void callAssign(ObjectClass objectClass, String url, String path, Uid uid, List<String> add, List<String> remove) {
        Stream<PatchOperation> addOp = add.stream().map(value -> new PatchOperation("add", path, value));
        Stream<PatchOperation> removeOp = remove.stream().map(value -> new PatchOperation("remove", path, value));
        List<PatchOperation> operations = Stream.concat(addOp, removeOp).collect(Collectors.toList());

        if (operations.isEmpty()) {
            LOG.info("No assign {0} {1} to {2} operations", objectClass.getObjectClassValue(), path, uid.getUidValue());
            return;
        }

        try (Response response = patch(url, operations)) {
            if (response.code() == 404) {
                // Missing the group
                throw new UnknownUidException(uid, objectClass);
            }

            if (response.code() != 204) {
                throw new ConnectorIOException(String.format("Failed to assign %s %s to %s, add: %s, remove: %s, statusCode: %d, response: %s",
                        objectClass.getObjectClassValue(), path, uid.getUidValue(), add, remove, response.code(), toBody(response)));
            }

            // Success

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to assign %s %s to %s, add: %s, remove: %s",
                    objectClass.getObjectClassValue(), path, uid.getUidValue(), add, remove), e);
        }
    }

    protected void callAssignConnections(ObjectClass objectClass, String url, String path, Uid uid, List<String> add, List<String> remove) {
        Stream<PatchOperation> addOp = add.stream().map(value -> new PatchOperation("add", path + value, "READ"));
        Stream<PatchOperation> removeOp = remove.stream().map(value -> new PatchOperation("remove", path + value, "READ"));
        List<PatchOperation> operations = Stream.concat(addOp, removeOp).collect(Collectors.toList());

        if (operations.isEmpty()) {
            LOG.info("No assign {0} {1} to {2} operations", objectClass.getObjectClassValue(), path, uid.getUidValue());
            return;
        }

        try (Response response = patch(url, operations)) {
            if (response.code() == 404) {
                // Missing the group
                throw new UnknownUidException(uid, objectClass);
            }

            if (response.code() != 204) {
                throw new ConnectorIOException(String.format("Failed to assign %s %s to %s, add: %s, remove: %s, statusCode: %d, response: %s",
                        objectClass.getObjectClassValue(), path, uid.getUidValue(), add, remove, response.code(), toBody(response)));
            }

            // Success

        } catch (IOException e) {
            throw new ConnectorIOException(String.format("Failed to assign %s %s to %s, add: %s, remove: %s",
                    objectClass.getObjectClassValue(), path, uid.getUidValue(), add, remove), e);
        }
    }

    private RequestBody createJsonRequestBody(Object body) {
        String bodyString;
        try {
            bodyString = MAPPER.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            throw new ConnectorIOException("Failed to write request json body", e);
        }

        return RequestBody.create(bodyString, MediaType.parse("application/json; charset=UTF-8"));
    }


    private void throwExceptionIfServerError(Response response) throws ConnectorIOException {
        if (response.code() >= 500 && response.code() <= 599) {
            try {
                String body = response.body().string();
                throw new ConnectorIOException("Guacamole server error: " + body);
            } catch (IOException e) {
                throw new ConnectorIOException("Guacamole server error", e);
            }
        }
    }

    private Response get(String url) throws IOException {
        for (int i = 0; i < 2; i++) {
            final Request request = new Request.Builder()
                    .url(url + "?token=" + getAuthToken())
                    .get()
                    .build();

            final Response response = httpClient.newCall(request).execute();

            if (response.code() == 403) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isUnauthorized()) {
                    // re-auth
                    auth();
                    continue;
                }
            }

            throwExceptionIfServerError(response);

            return response;
        }

        throw new ConnectorIOException("Failed to call get API");
    }

    private Response post(String url, Object body) throws IOException {
        RequestBody requestBody = createJsonRequestBody(body);

        for (int i = 0; i < 2; i++) {
            final Request request = new Request.Builder()
                    .url(url + "?token=" + getAuthToken())
                    .post(requestBody)
                    .build();

            final Response response = httpClient.newCall(request).execute();

            if (response.code() == 403) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isUnauthorized()) {
                    // re-auth
                    auth();
                    continue;
                }
            }

            throwExceptionIfServerError(response);

            return response;
        }

        throw new ConnectorIOException("Failed to call post API");
    }

    private Response put(String url, Object body) throws IOException {
        RequestBody requestBody = createJsonRequestBody(body);

        for (int i = 0; i < 2; i++) {
            final Request request = new Request.Builder()
                    .url(url + "?token=" + getAuthToken())
                    .put(requestBody)
                    .build();

            final Response response = httpClient.newCall(request).execute();

            if (response.code() == 403) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isUnauthorized()) {
                    // re-auth
                    auth();
                    continue;
                }
            }

            throwExceptionIfServerError(response);

            return response;
        }

        throw new ConnectorIOException("Failed to call post API");
    }

    private Response patch(String url, Object body) throws IOException {
        RequestBody requestBody = createJsonRequestBody(body);

        for (int i = 0; i < 2; i++) {
            final Request request = new Request.Builder()
                    .url(url + "?token=" + getAuthToken())
                    .patch(requestBody)
                    .build();

            final Response response = httpClient.newCall(request).execute();

            if (response.code() == 403) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isUnauthorized()) {
                    // re-auth
                    auth();
                    continue;
                }
            }

            throwExceptionIfServerError(response);

            return response;
        }

        throw new ConnectorIOException("Failed to call patch API");
    }

    private Response delete(String url) throws IOException {
        for (int i = 0; i < 2; i++) {
            final Request request = new Request.Builder()
                    .url(url + "?token=" + getAuthToken())
                    .delete()
                    .build();

            final Response response = httpClient.newCall(request).execute();

            if (response.code() == 403) {
                GuacamoleErrorRepresentation error = MAPPER.readValue(response.body().byteStream(), GuacamoleErrorRepresentation.class);
                if (error.isUnauthorized()) {
                    // re-auth
                    auth();
                    continue;
                }
            }

            throwExceptionIfServerError(response);

            return response;
        }

        throw new ConnectorIOException("Failed to call delete API");
    }
}
