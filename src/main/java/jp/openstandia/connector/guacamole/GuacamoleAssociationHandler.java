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
import org.identityconnectors.framework.common.objects.Uid;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class GuacamoleAssociationHandler {

    private static final Log LOGGER = Log.getLog(GuacamoleAssociationHandler.class);

    private final GuacamoleConfiguration configuration;
    private final GuacamoleClient client;

    public GuacamoleAssociationHandler(GuacamoleConfiguration configuration, GuacamoleClient client) {
        this.configuration = configuration;
        this.client = client;
    }

    public void addUserGroupsToUser(Uid uid, List<Object> addGroups) {
        updateUserGroupsToUser(uid, addGroups, Collections.EMPTY_LIST);
    }

    public void updateUserGroupsToUser(Uid uid, List<Object> addGroups, List<Object> removeGroups) {
        if (isEmpty(addGroups) && isEmpty(removeGroups)) {
            return;
        }
        client.assignUserGroupsToUser(uid, toList(addGroups), toList(removeGroups));
    }

    public List<String> getUserGroupsForUser(String username) {
        List<String> groups = new ArrayList<>();
        getUserGroupsForUser(username, groupName -> {
            groups.add(groupName);
            return true;
        });
        return groups;
    }

    public void getUserGroupsForUser(String userName, GuacamoleQueryHandler<String> handler) {
        client.getUserGroupsForUser(userName, handler);
    }

    public void addUsersToUserGroup(Uid uid, List<Object> addUsers) {
        updateUsersToUserGroup(uid, addUsers, Collections.EMPTY_LIST);
    }

    public void updateUsersToUserGroup(Uid uid, List<Object> addUsers, List<Object> removeUsers) {
        if (isEmpty(addUsers) && isEmpty(removeUsers)) {
            return;
        }
        client.assignUserGroupsToUser(uid, toList(addUsers), toList(removeUsers));
    }

    public List<String> getUsersForUserGroup(String groupName) {
        List<String> users = new ArrayList<>();
        getUsersForUserGroup(groupName, username -> {
            users.add(username);
            return true;
        });
        return users;
    }

    public void getUsersForUserGroup(String groupName, GuacamoleQueryHandler<String> handler) {
        client.getUsersForUserGroup(groupName, handler);
    }

    // Group-Group

    public void addUserGroupsToUserGroup(Uid uid, List<Object> addGroups) {
        updateUserGroupsToUserGroup(uid, addGroups, Collections.EMPTY_LIST);
    }

    public void updateUserGroupsToUserGroup(Uid uid, List<Object> addGroups, List<Object> removeGroups) {
        if (isEmpty(addGroups) && isEmpty(removeGroups)) {
            return;
        }
        client.assignUserGroupsToUserGroup(uid, toList(addGroups), toList(removeGroups));
    }

    public List<String> getUserGroupsForUserGroup(String groupName) {
        List<String> groups = new ArrayList<>();
        getUserGroupsForUserGroup(groupName, username -> {
            groups.add(username);
            return true;
        });
        return groups;
    }

    public void getUserGroupsForUserGroup(String groupName, GuacamoleQueryHandler<String> handler) {
        client.getUserGroupsForUserGroup(groupName, handler);
    }

    // Permission

    public void addUserPermissionsToUser(Uid userUid, List<Object> addPermissions) {
        updateUserPermissionsToUser(userUid, addPermissions, Collections.EMPTY_LIST);
    }

    public void updateUserPermissionsToUser(Uid userUid, List<Object> addPermissions, List<Object> removePermissions) {
        if (isEmpty(addPermissions) && isEmpty(removePermissions)) {
            return;
        }
        client.assignUserPermissionsToUser(userUid, toList(addPermissions), toList(removePermissions));
    }

    public void addSystemPermissionsToUser(Uid userUid, List<Object> addPermissions) {
        updateSystemPermissionsToUser(userUid, addPermissions, Collections.EMPTY_LIST);
    }

    public void updateSystemPermissionsToUser(Uid userUid, List<Object> addPermissions, List<Object> removePermissions) {
        if (isEmpty(addPermissions) && isEmpty(removePermissions)) {
            return;
        }
        client.assignSystemPermissionsToUser(userUid, toList(addPermissions), toList(removePermissions));
    }

    public void addSystemPermissionsToGroup(Uid groupUid, List<Object> addPermissions) {
        updateSystemPermissionsToGroup(groupUid, addPermissions, Collections.EMPTY_LIST);
    }

    public void updateSystemPermissionsToGroup(Uid groupUid, List<Object> addPermissions, List<Object> removePermissions) {
        if (isEmpty(addPermissions) && isEmpty(removePermissions)) {
            return;
        }
        client.assignSystemPermissionsToUserGroup(groupUid, toList(addPermissions), toList(removePermissions));
    }

    // Connection
    public void addConnectionsToUser(Uid userUid, List<Object> addConnections) {
        updateConnectionsToUser(userUid, addConnections, Collections.EMPTY_LIST);
    }

    public void updateConnectionsToUser(Uid userUid, List<Object> addConnections, List<Object> removeConnections) {
        if (isEmpty(addConnections) && isEmpty(removeConnections)) {
            return;
        }
        client.assignConnectionsToUser(userUid, toList(addConnections), toList(removeConnections));
    }

    public void addConnectionsToUserGroup(Uid userGroupUid, List<Object> addConnections) {
        updateConnectionsToUserGroup(userGroupUid, addConnections, Collections.EMPTY_LIST);
    }

    public void updateConnectionsToUserGroup(Uid userGroupUid, List<Object> addConnections, List<Object> removeConnections) {
        if (isEmpty(addConnections) && isEmpty(removeConnections)) {
            return;
        }
        client.assignConnectionsToUserGroup(userGroupUid, toList(addConnections), toList(removeConnections));
    }

    // ConnectionGroup
    public void addConnectionGroupsToUser(Uid userUid, List<Object> addConnections) {
        updateConnectionGroupsToUser(userUid, addConnections, Collections.EMPTY_LIST);
    }

    public void updateConnectionGroupsToUser(Uid userUid, List<Object> addConnectionGroups, List<Object> removeConnectionGroups) {
        if (isEmpty(addConnectionGroups) && isEmpty(removeConnectionGroups)) {
            return;
        }
        client.assignConnectionGroupsToUser(userUid, toList(addConnectionGroups), toList(removeConnectionGroups));
    }

    public void addConnectionGroupsToUserGroup(Uid userGroupUid, List<Object> addConnections) {
        updateConnectionGroupsToUserGroup(userGroupUid, addConnections, Collections.EMPTY_LIST);
    }

    public void updateConnectionGroupsToUserGroup(Uid userGroupUid, List<Object> addConnectionGroups, List<Object> removeConnectionGroups) {
        if (isEmpty(addConnectionGroups) && isEmpty(removeConnectionGroups)) {
            return;
        }
        client.assignConnectionGroupsToUserGroup(userGroupUid, toList(addConnectionGroups), toList(removeConnectionGroups));
    }

    // Utilities

    private <T> Stream<T> streamNullable(Collection<T> list) {
        if (list == null) {
            return Stream.empty();
        }
        return list.stream();
    }

    private List<String> toList(Collection<?> list) {
        return streamNullable(list).map(x -> x.toString()).collect(Collectors.toList());
    }

    private boolean isEmpty(List<Object> list) {
        return list == null || list.isEmpty();
    }

}
