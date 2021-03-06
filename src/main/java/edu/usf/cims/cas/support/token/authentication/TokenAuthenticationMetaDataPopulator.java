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
package edu.usf.cims.cas.support.token.authentication;

import edu.usf.cims.cas.support.token.authentication.principal.TokenCredential;
import org.jasig.cas.authentication.AuthenticationBuilder;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is a meta data populator for authentication using an encrypted JSON object as a token. 
 * 
 * @author Eric Pierce
 * @since 0.1
 */
public final class TokenAuthenticationMetaDataPopulator implements AuthenticationMetaDataPopulator {

  private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticationMetaDataPopulator.class);
    
  public void populateAttributes(AuthenticationBuilder authenticationBuilder, Credential credential) {

    if (credential instanceof TokenCredential) {
      TokenCredential tokenCredential = (TokenCredential) credential;
      final Principal simplePrincipal = new SimplePrincipal(authenticationBuilder.getPrincipal().getId(),
                                                              tokenCredential.getUserAttributes());

      logger.debug("attributes : {}",simplePrincipal.getAttributes());
    }
  }
}