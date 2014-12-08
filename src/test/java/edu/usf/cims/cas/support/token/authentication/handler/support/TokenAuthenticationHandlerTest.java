package edu.usf.cims.cas.support.token.authentication.handler.support;

import edu.clayton.cas.support.token.keystore.JSONKeystore;
import edu.usf.cims.cas.support.token.authentication.principal.TokenCredential;
import static org.hamcrest.CoreMatchers.instanceOf;
import org.jasig.cas.authentication.HandlerResult;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.net.URL;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThat;

public class TokenAuthenticationHandlerTest {
  private String b64Token =
      "9WV+J40K+tfISLlliYwx320WrfUpfkPN2uCelSOxaN+JgfdPSr9E4qYTbvei0mmEXcUNczygVbW6\n" +
      "Qk8BpsMPqTnos9TWx8NPLKk1ghykEES1gOVCcUzMqx4C+0sFbUsSs3Ory8KBjNzM/eAv0Cd0ZKnn\n" +
      "mbo5Y94Pl+ZQzDd+sWCBD3swENa018rNyQ1IGVbYHRbooJvtfsY/aJu+GPkL3+zE4YxKYnBZYqxV\n" +
      "d7+T4iE=";

  private TokenAuthenticationHandler handler;
  private TokenCredential validCredential;
  private TokenCredential invalidCredential;

  @Before
  public void setup() {
    this.handler = new TokenAuthenticationHandler();
    this.validCredential = new TokenCredential(
        "jsumners",
        this.b64Token,
        "alphabet_key"
    );
    this.invalidCredential = new TokenCredential(
        "jsumners",
        this.b64Token,
        "number_key"
    );
  }

  @Test
  public void testSupports() {
    assertTrue(this.handler.supports(validCredential));
  }

  @Test
  public void testAuthSuccess() throws Exception {
    URL url = this.getClass().getClassLoader().getResource("testHandlerStoreWithGoodKey.json");
    File keystoreFile = new File(url.toURI());
    JSONKeystore jsonKeystore = new JSONKeystore(keystoreFile);

    this.handler.setKeystore(jsonKeystore);
    this.handler.setMaxDrift(Integer.MAX_VALUE);

    assertThat(this.handler.authenticate(this.validCredential), instanceOf(HandlerResult.class));
  }

  @Test(expected = GeneralSecurityException.class)
  public void testAuthFailure() throws Exception {
    URL url = this.getClass().getClassLoader().getResource("testHandlerStoreWithBadKey.json");
    File keystoreFile = new File(url.toURI());
    JSONKeystore jsonKeystore = new JSONKeystore(keystoreFile);

    this.handler.setKeystore(jsonKeystore);
    this.handler.setMaxDrift(Integer.MAX_VALUE);

    HandlerResult result = this.handler.authenticate(this.invalidCredential);

    assertFalse(result.getWarnings().isEmpty());
  }
}