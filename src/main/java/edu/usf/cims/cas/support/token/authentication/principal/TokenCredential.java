/* Copyright 2013 University of South Florida.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package edu.usf.cims.cas.support.token.authentication.principal;

import edu.clayton.cas.support.token.Token;
import edu.clayton.cas.support.token.TokenAttributes;
import org.jasig.cas.authentication.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * This class creates a CAS-compatible credential using data from an AES128-encrypted token
 *
 * @author Eric Pierce
 * @since 0.1
 */
public final class TokenCredential implements Credential {

    private static final long serialVersionUID = 2749515041385101770L;

    private static final Logger log = LoggerFactory.getLogger(TokenCredential.class);

    private Token token;

    private String username;

    private String tokenService;

    private Map<String, Object> userAttributes;

    /**
     *
     * @param username
     * @param token
     * @param tokenService
     */
    public TokenCredential(final String username, final String token, final String tokenService) {
        Assert.notNull(token, "token cannot be null");
        Assert.notNull(username, "username cannot be null");
        Assert.notNull(tokenService, "tokenService cannot be null");
        this.token = new Token(token);
        this.tokenService = tokenService;
        this.username = username;
    }

    /**
     *
     * @return
     */
    public String getId() {
        return this.username;
    }

    /**
     *
     * @param token
     */
    public final void setToken(final Token token) {
        this.token = token;
    }

    /**
     *
     * @return
     */
    public final Token getToken() {
        return this.token;
    }

    /**
     *
     * @return
     */
    public final String getTokenService() {
        return this.tokenService;
    }

    /**
     *
     * @param username
     */
    public final void setUsername(final String username) {
        this.username = username;
    }

    /**
     *
     * @return
     */
    public final String getUsername() {
        return this.username;
    }

    /**
     *
     * @return
     */
    public final Map<String, Object> getUserAttributes() {
        return this.userAttributes;
    }


    /**
     * Create a map of the user's attributes for use by the CAS server classes.
     *
     * @param userProfile The {@link }
     */
    public void setUserAttributes(TokenAttributes userProfile) {
        Assert.notNull(userProfile);
        this.userAttributes = userProfile;
    }

    /**
     *
     * @return
     */
    public String toString() {
        if (this.userAttributes != null && this.userAttributes.containsKey("PreferredUsername")) {
            return (String) userAttributes.get("PreferredUsername");
        } else {
            return "[authentication token: " + this.username + ":" + this.token + "]";
        }
    }
}
