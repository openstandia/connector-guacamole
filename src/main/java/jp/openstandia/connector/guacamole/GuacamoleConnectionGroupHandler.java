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

import java.util.Set;

import static jp.openstandia.connector.guacamole.GuacamoleUtils.*;

public class GuacamoleConnectionGroupHandler implements GuacamoleObjectHandler {

    public static final ObjectClass CONNECTION_GROUP_OBJECT_CLASS = new ObjectClass("ConnectionGroup");

    private static final Log LOGGER = Log.getLog(GuacamoleConnectionGroupHandler.class);

    // Unique, auto-generated and unchangeable within the guacamole server
    private static final String ATTR_IDENTIFIER = "identifier";
    // Unique and changeable within the guacamole server
    // This is composed by 'parentIdentifier' and 'name' to make it unique
    // The format is <parentIdentifier>/<name>
    private static final String ATTR_NAME_WITH_PARENT_IDENTIFIER = "name-with-parentIdentifier";
    // ORGANIZATIONAL or BALANCING
    private static final String ATTR_TYPE = "type";

    // Attributes
    private static final String ATTR_ENABLE_SESSION_AFFINITY = "enable-session-affinity";
    private static final String ATTR_MAX_CONNECTIONS = "max-connections";
    private static final String ATTR_MAX_CONNECTIONS_PER_USER = "max-connections-per-user";

    private final GuacamoleConfiguration configuration;
    private final GuacamoleClient client;
    private final GuacamoleSchema schema;
    private final GuacamoleAssociationHandler associationHandler;

    public GuacamoleConnectionGroupHandler(GuacamoleConfiguration configuration, GuacamoleClient client, GuacamoleSchema schema) {
        this.configuration = configuration;
        this.client = client;
        this.schema = schema;
        this.associationHandler = new GuacamoleAssociationHandler(configuration, client);
    }

    public static ObjectClassInfo createSchema() {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(CONNECTION_GROUP_OBJECT_CLASS.getObjectClassValue());

        // identifier __UID__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(false)
                .setCreateable(false)
                .setUpdateable(false)
                .setNativeName(ATTR_IDENTIFIER)
                .build());
        // identifier __NAME__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setCreateable(true)
                .setUpdateable(true)
                .setNativeName(ATTR_NAME_WITH_PARENT_IDENTIFIER)
                .build());

        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_TYPE)
                        .setRequired(true)
                        .setCreateable(true)
                        .setUpdateable(true)
                        .build()
        );

        // Attributes
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_ENABLE_SESSION_AFFINITY)
                        .setRequired(false)
                        .setCreateable(true)
                        .setUpdateable(true)
                        .setType(Boolean.class)
                        .build()
        );
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_MAX_CONNECTIONS)
                        .setRequired(false)
                        .setCreateable(true)
                        .setUpdateable(true)
                        .setType(Integer.class)
                        .build()
        );
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_MAX_CONNECTIONS_PER_USER)
                        .setRequired(false)
                        .setCreateable(true)
                        .setUpdateable(true)
                        .setType(Integer.class)
                        .build()
        );

        ObjectClassInfo schemaInfo = builder.build();

        LOGGER.info("The constructed ConnectionGroup core schema: {0}", schemaInfo);

        return schemaInfo;
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
        Uid newUid = client.createConnectionGroup(schema, attributes);

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
        try {
            if (!modifications.isEmpty()) {
                client.updateConnectionGroup(schema, uid, modifications, options);
            }

        } catch (UnknownUidException e) {
            LOGGER.warn("Not found connectionGroup when updating. uid: {0}", uid);
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
            client.deleteConnectionGroup(schema, uid, options);

        } catch (UnknownUidException e) {
            LOGGER.warn("Not found connectionGroup when deleting. uid: {0}", uid);
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
        Set<String> attributesToGet = createFullAttributesToGet(schema.connectionGroupSchema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null) {
            if (filter.isByUid()) {
                getByUid(filter.attributeValue, resultsHandler, options, attributesToGet, allowPartialAttributeValues);
                return;
            } else {
                getByName(filter.attributeValue, resultsHandler, options, attributesToGet, allowPartialAttributeValues);
                return;
            }
        }

        client.getConnectionGroups(schema, conn -> resultsHandler.handle(toConnectorObject(conn, attributesToGet, allowPartialAttributeValues)),
                options, attributesToGet, -1);
    }

    private void getByUid(String attributeValue, ResultsHandler resultsHandler, OperationOptions options, Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        GuacamoleClient.GuacamoleConnectionGroupRepresentation conn = client.getConnectionGroup(schema, new Uid(attributeValue), options, attributesToGet);

        if (conn != null) {
            resultsHandler.handle(toConnectorObject(conn, attributesToGet, allowPartialAttributeValues));
        }
    }

    private void getByName(String attributeValue, ResultsHandler resultsHandler, OperationOptions options, Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        GuacamoleClient.GuacamoleConnectionGroupRepresentation conn = client.getConnectionGroup(schema, new Name(attributeValue), options, attributesToGet);

        if (conn != null) {
            resultsHandler.handle(toConnectorObject(conn, attributesToGet, allowPartialAttributeValues));
        }
    }

    private ConnectorObject toConnectorObject(GuacamoleClient.GuacamoleConnectionGroupRepresentation conn,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues) {

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(CONNECTION_GROUP_OBJECT_CLASS)
                // Need to set __UID__ and __NAME__ because it throws IllegalArgumentException
                .setUid(conn.identifier)
                .setName(conn.toUniqueName());

        builder.addAttribute(AttributeBuilder.build(ATTR_TYPE, conn.type));

        for (GuacamoleAttribute a : conn.toGuacamoleAttributes()) {
            AttributeInfo attributeInfo = schema.connectionGroupSchema.get(a.name);
            if (attributeInfo == null || a.value == null) {
                continue;
            }
            if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                builder.addAttribute(toConnectorAttribute(attributeInfo, a));
            }
        }

        return builder.build();
    }
}
