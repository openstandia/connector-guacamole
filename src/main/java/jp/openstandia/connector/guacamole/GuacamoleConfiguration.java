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
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

public class GuacamoleConfiguration extends AbstractConfiguration {

    private String guacamoleURL;
    private String guacamoleDataSource;
    private String apiUsername;
    private GuardedString apiPassword;
    private String httpProxyHost;
    private int httpProxyPort;
    private String httpProxyUser;
    private GuardedString httpProxyPassword;
    private boolean suppressInvitationMessageEnabled = true;
    private int connectionTimeoutInMilliseconds = 20000;
    private int readTimeoutInMilliseconds = 15000;
    private int writeTimeoutInMilliseconds = 15000;

    @ConfigurationProperty(
            order = 1,
            displayMessageKey = "Guacamole API URL",
            helpMessageKey = "Guacamole API URL which is connected from this connector. e.g. https://guacamole.example.com/guacamole/api",
            required = true,
            confidential = false)
    public String getGuacamoleURL() {
        if (guacamoleURL != null && !guacamoleURL.endsWith("/")) {
            return guacamoleURL + "/";
        }
        return guacamoleURL;
    }

    public void setGuacamoleURL(String guacamoleURL) {
        this.guacamoleURL = guacamoleURL;
    }

    @ConfigurationProperty(
            order = 2,
            displayMessageKey = "Guacamole Data source",
            helpMessageKey = "Guacamole Data source which is connected from this connector. e.g. postgresql-shared",
            required = true,
            confidential = false)
    public String getGuacamoleDataSource() {
        return guacamoleDataSource;
    }

    public void setGuacamoleDataSource(String guacamoleDataSource) {
        this.guacamoleDataSource = guacamoleDataSource;
    }

    @ConfigurationProperty(
            order = 3,
            displayMessageKey = "Guacamole API Username",
            helpMessageKey = "Username for the API authentication.",
            required = true,
            confidential = false)
    public String getApiUsername() {
        return apiUsername;
    }

    public void setApiUsername(String apiUsername) {
        this.apiUsername = apiUsername;
    }

    @ConfigurationProperty(
            order = 4,
            displayMessageKey = "Guacamole API Password",
            helpMessageKey = "Password for the API authentication.",
            required = true,
            confidential = false)
    public GuardedString getApiPassword() {
        return apiPassword;
    }

    public void setApiPassword(GuardedString apiPassword) {
        this.apiPassword = apiPassword;
    }

    @ConfigurationProperty(
            order = 5,
            displayMessageKey = "HTTP Proxy Host",
            helpMessageKey = "Hostname for the HTTP Proxy",
            required = false,
            confidential = false)
    public String getHttpProxyHost() {
        return httpProxyHost;
    }

    public void setHttpProxyHost(String httpProxyHost) {
        this.httpProxyHost = httpProxyHost;
    }

    @ConfigurationProperty(
            order = 6,
            displayMessageKey = "HTTP Proxy Port",
            helpMessageKey = "Port for the HTTP Proxy",
            required = false,
            confidential = false)
    public int getHttpProxyPort() {
        return httpProxyPort;
    }

    public void setHttpProxyPort(int httpProxyPort) {
        this.httpProxyPort = httpProxyPort;
    }

    @ConfigurationProperty(
            order = 7,
            displayMessageKey = "HTTP Proxy User",
            helpMessageKey = "Username for the HTTP Proxy Authentication",
            required = false,
            confidential = false)
    public String getHttpProxyUser() {
        return httpProxyUser;
    }

    public void setHttpProxyUser(String httpProxyUser) {
        this.httpProxyUser = httpProxyUser;
    }

    @ConfigurationProperty(
            order = 8,
            displayMessageKey = "HTTP Proxy Password",
            helpMessageKey = "Password for the HTTP Proxy Authentication",
            required = false,
            confidential = true)
    public GuardedString getHttpProxyPassword() {
        return httpProxyPassword;
    }

    public void setHttpProxyPassword(GuardedString httpProxyPassword) {
        this.httpProxyPassword = httpProxyPassword;
    }

    @ConfigurationProperty(
            order = 9,
            displayMessageKey = "Connection Timeout (in milliseconds)",
            helpMessageKey = "Connection timeout when connecting to Guacamole API. (Default: 20000)",
            required = false,
            confidential = false)
    public int getConnectionTimeoutInMilliseconds() {
        return connectionTimeoutInMilliseconds;
    }

    public void setConnectionTimeoutInMilliseconds(int connectionTimeoutInMilliseconds) {
        this.connectionTimeoutInMilliseconds = connectionTimeoutInMilliseconds;
    }

    @ConfigurationProperty(
            order = 10,
            displayMessageKey = "Connection Read Timeout (in milliseconds)",
            helpMessageKey = "Connection read timeout when connecting to Guacamole API. (Default: 15000)",
            required = false,
            confidential = false)
    public int getReadTimeoutInMilliseconds() {
        return readTimeoutInMilliseconds;
    }

    public void setReadTimeoutInMilliseconds(int readTimeoutInMilliseconds) {
        this.readTimeoutInMilliseconds = readTimeoutInMilliseconds;
    }

    @ConfigurationProperty(
            order = 11,
            displayMessageKey = "Connection Write Timeout (in milliseconds)",
            helpMessageKey = "Connection write timeout when connecting to Guacamole API. (Default: 15000)",
            required = false,
            confidential = false)
    public int getWriteTimeoutInMilliseconds() {
        return writeTimeoutInMilliseconds;
    }

    public void setWriteTimeoutInMilliseconds(int writeTimeoutInMilliseconds) {
        this.writeTimeoutInMilliseconds = writeTimeoutInMilliseconds;
    }
    
    @Override
    public void validate() {
        if (guacamoleURL == null) {
            throw new ConfigurationException("Guacamole URL is required");
        }
        if (guacamoleDataSource == null) {
            throw new ConfigurationException("Guacamole Data source is required");
        }
        if (apiUsername == null) {
            throw new ConfigurationException("Guacamole API Username is required");
        }
        if (apiPassword == null) {
            throw new ConfigurationException("Guacamole API Password is required");
        }
    }
}
