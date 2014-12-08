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

import com.sun.istack.NotNull;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.principal.PersonDirectoryPrincipalResolver;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.services.persondir.IPersonAttributeDao;

/**
 * Created by kelseyc on 12/5/2014.
 */
public class TokenCredentialToPrincipalResolver {

    @NotNull
    private PersonDirectoryPrincipalResolver attributeRepository = new PersonDirectoryPrincipalResolver();

    protected String extractPrincipalId(final Credential credential) {
        TokenCredential tokenCredential = (TokenCredential) credential;
        String principal = tokenCredential.getUsername();
        return principal;
    }

    public final Principal resolvePrincipal(final Credential credential) {
        return attributeRepository.resolve(credential);
    }

    public boolean supports(final Credential credential) {
        return credential != null && (TokenCredential.class.isAssignableFrom(credential.getClass()));
    }
}
