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
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

public class GuacamoleFilterTranslator extends AbstractFilterTranslator<GuacamoleFilter> {

    private static final Log LOG = Log.getLog(GuacamoleFilterTranslator.class);

    private final OperationOptions options;
    private final ObjectClass objectClass;

    public GuacamoleFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        this.objectClass = objectClass;
        this.options = options;
    }

    @Override
    protected GuacamoleFilter createEqualsExpression(EqualsFilter filter, boolean not) {
        if (not) { // no way (natively) to search for "NotEquals"
            return null;
        }
        Attribute attr = filter.getAttribute();

        if (attr instanceof Uid) {
            Uid uid = (Uid) attr;
            GuacamoleFilter nameFilter = new GuacamoleFilter(uid.getName(),
                    GuacamoleFilter.FilterType.EXACT_MATCH,
                    uid.getUidValue());
            return nameFilter;
        }
        if (attr instanceof Name) {
            Name name = (Name) attr;
            GuacamoleFilter nameFilter = new GuacamoleFilter(name.getName(),
                    GuacamoleFilter.FilterType.EXACT_MATCH,
                    name.getNameValue());
            return nameFilter;
        }

        // Guacamole doesn't support searching by other attributes
        return null;
    }
}
