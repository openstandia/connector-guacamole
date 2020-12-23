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

import jp.openstandia.connector.guacamole.testutil.AbstractTest;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.Schema;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SchemaTest extends AbstractTest {

    @Test
    void schema() {
        Schema schema = connector.schema();

        assertNotNull(schema);
        assertEquals(4, schema.getObjectClassInfo().size());

        Optional<ObjectClassInfo> user = schema.getObjectClassInfo().stream().filter(o -> o.is("User")).findFirst();
        Optional<ObjectClassInfo> group = schema.getObjectClassInfo().stream().filter(o -> o.is("UserGroup")).findFirst();
        Optional<ObjectClassInfo> connection = schema.getObjectClassInfo().stream().filter(o -> o.is("Connection")).findFirst();
        Optional<ObjectClassInfo> connectionGroup = schema.getObjectClassInfo().stream().filter(o -> o.is("ConnectionGroup")).findFirst();

        assertTrue(user.isPresent());
        assertTrue(group.isPresent());
        assertTrue(connection.isPresent());
        assertTrue(connectionGroup.isPresent());
    }
}
