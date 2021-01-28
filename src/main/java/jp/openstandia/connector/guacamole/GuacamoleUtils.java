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

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Provides utility methods
 *
 * @author Hiroyuki Wada
 */
public class GuacamoleUtils {

    public static ZonedDateTime toZoneDateTime(Instant instant) {
        ZoneId zone = ZoneId.systemDefault();
        return ZonedDateTime.ofInstant(instant, zone);
    }

    public static ZonedDateTime toZoneDateTime(String yyyymmdd) {
        LocalDate date = LocalDate.parse(yyyymmdd);
        return date.atStartOfDay(ZoneId.systemDefault());
    }

    /**
     * Transform a Guacamole attribute object to a Connector attribute object.
     *
     * @param attributeInfo
     * @param a
     * @return
     */
    public static Attribute toConnectorAttribute(AttributeInfo attributeInfo, GuacamoleAttribute a) {
        // Guacamole API returns the attribute as string even if it's other types.
        // We need to check the type from the schema and convert it.
        if (attributeInfo.getType() == Integer.class) {
            return AttributeBuilder.build(a.name, Integer.parseInt(a.value));
        }
        if (attributeInfo.getType() == ZonedDateTime.class) {
            // The format is YYYY-MM-DD
            return AttributeBuilder.build(a.name, toZoneDateTime(a.value));
        }
        if (attributeInfo.getType() == Boolean.class) {
            return AttributeBuilder.build(a.name, Boolean.parseBoolean(a.value));
        }
        if (attributeInfo.getType() == GuardedString.class) {
            return AttributeBuilder.build(a.name, new GuardedString(a.value.toCharArray()));
        }

        // String
        return AttributeBuilder.build(a.name, a.value);
    }

    public static GuacamoleAttribute toGuacamoleAttribute(Map<String, AttributeInfo> schema, AttributeDelta delta) {
        return new GuacamoleAttribute(delta.getName(), toGuacamoleValue(schema, delta));
    }

    /**
     * Transform a Connector attribute object to a Guacamole attribute object.
     *
     * @param schema
     * @param attr
     * @return
     */
    public static GuacamoleAttribute toGuacamoleAttribute(Map<String, AttributeInfo> schema, Attribute attr) {
        return new GuacamoleAttribute(attr.getName(), toGuacamoleValue(schema, attr));
    }

    private static String toGuacamoleValue(Map<String, AttributeInfo> schema, AttributeDelta delta) {
        AttributeInfo attributeInfo = schema.get(delta.getName());
        if (attributeInfo == null) {
            throw new InvalidAttributeValueException("Invalid attribute. name: " + delta.getName());
        }

        String rtn = null;

        if (attributeInfo.getType() == Integer.class) {
            rtn = AttributeDeltaUtil.getAsStringValue(delta);

        } else if (attributeInfo.getType() == ZonedDateTime.class) {
            // The format must be YYYY-MM-DD in guacamole
            ZonedDateTime date = (ZonedDateTime) AttributeDeltaUtil.getSingleValue(delta);
            rtn = date.format(DateTimeFormatter.ISO_LOCAL_DATE);

        } else if (attributeInfo.getType() == Boolean.class) {
            // Use "" for false value in Guacamole API
            if (Boolean.FALSE.equals(AttributeDeltaUtil.getBooleanValue(delta))) {
                return "";
            }
            rtn = AttributeDeltaUtil.getAsStringValue(delta);

        } else if (attributeInfo.getType() == GuardedString.class) {
            GuardedString gs = AttributeDeltaUtil.getGuardedStringValue(delta);
            if (gs == null) {
                return "";
            }
            AtomicReference<String> value = new AtomicReference<>();
            gs.access(v -> {
                value.set(String.valueOf(v));
            });
            rtn = value.get();

        } else {
            rtn = AttributeDeltaUtil.getAsStringValue(delta);
        }

        if (rtn == null) {
            // To remove, return empty string
            return "";
        }
        return rtn;
    }

    private static String toGuacamoleValue(Map<String, AttributeInfo> schema, Attribute attr) {
        AttributeInfo attributeInfo = schema.get(attr.getName());
        if (attributeInfo == null) {
            throw new InvalidAttributeValueException("Invalid attribute. name: " + attr.getName());
        }

        String rtn = null;

        if (attributeInfo.getType() == Integer.class) {
            rtn = AttributeUtil.getAsStringValue(attr);

        } else if (attributeInfo.getType() == ZonedDateTime.class) {
            // The format must be YYYY-MM-DD in guacamole
            ZonedDateTime date = (ZonedDateTime) AttributeUtil.getSingleValue(attr);
            rtn = date.format(DateTimeFormatter.ISO_LOCAL_DATE);

        } else if (attributeInfo.getType() == Boolean.class) {
            // Use "" for false value in Guacamole API
            if (Boolean.FALSE.equals(AttributeUtil.getBooleanValue(attr))) {
                return "";
            }
            rtn = AttributeUtil.getAsStringValue(attr);

        } else if (attributeInfo.getType() == GuardedString.class) {
            GuardedString gs = AttributeUtil.getGuardedStringValue(attr);
            if (gs == null) {
                return "";
            }
            AtomicReference<String> value = new AtomicReference<>();
            gs.access(v -> {
                value.set(String.valueOf(v));
            });
            rtn = value.get();

        } else {
            rtn = AttributeUtil.getAsStringValue(attr);
        }

        if (rtn == null) {
            // To remove, return empty string
            return "";
        }
        return rtn;
    }

    /**
     * Check if attrsToGetSet contains the attribute.
     *
     * @param attrsToGetSet
     * @param attr
     * @return
     */
    public static boolean shouldReturn(Set<String> attrsToGetSet, String attr) {
        if (attrsToGetSet == null) {
            return true;
        }
        return attrsToGetSet.contains(attr);
    }

    /**
     * Check if ALLOW_PARTIAL_ATTRIBUTE_VALUES == true.
     *
     * @param options
     * @return
     */
    public static boolean shouldAllowPartialAttributeValues(OperationOptions options) {
        // If the option isn't set from IDM, it may be null.
        return Boolean.TRUE.equals(options.getAllowPartialAttributeValues());
    }

    /**
     * Check if RETURN_DEFAULT_ATTRIBUTES == true.
     *
     * @param options
     * @return
     */
    public static boolean shouldReturnDefaultAttributes(OperationOptions options) {
        // If the option isn't set from IDM, it may be null.
        return Boolean.TRUE.equals(options.getReturnDefaultAttributes());
    }

    /**
     * Create full set of ATTRIBUTES_TO_GET which is composed by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET.
     *
     * @param schema
     * @param options
     * @return
     */
    public static Set<String> createFullAttributesToGet(Map<String, AttributeInfo> schema, OperationOptions options) {
        Set<String> attributesToGet = null;
        if (shouldReturnDefaultAttributes(options)) {
            attributesToGet = new HashSet<>();
            attributesToGet.addAll(toReturnedByDefaultAttributesSet(schema));
        }
        if (options.getAttributesToGet() != null) {
            if (attributesToGet == null) {
                attributesToGet = new HashSet<>();
            }
            for (String a : options.getAttributesToGet()) {
                attributesToGet.add(a);
            }
        }
        return attributesToGet;
    }

    private static Set<String> toReturnedByDefaultAttributesSet(Map<String, AttributeInfo> schema) {
        return schema.entrySet().stream()
                .filter(entry -> entry.getValue().isReturnedByDefault())
                .map(entry -> entry.getKey())
                .collect(Collectors.toSet());
    }
}
