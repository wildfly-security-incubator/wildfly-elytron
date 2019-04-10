package org.wildfly.security.auth.client.webservices;

import org.jboss.wsf.spi.security.WildflyClientSecurityConfigProvider;
import org.jboss.wsf.spi.security.WildflyClientConfigException;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;

import javax.net.ssl.SSLContext;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.net.URI;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;

import org.kohsuke.MetaInfServices;

@MetaInfServices(value = WildflyClientSecurityConfigProvider.class)
public class WebServicesClientConfigurationProviderImpl implements WildflyClientSecurityConfigProvider {

    private static final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
    private AuthenticationContext authenticationContext = AuthenticationContext.captureCurrent();

    public SSLContext getSSLContext(URI uri) throws WildflyClientConfigException {
        try {
            return AUTH_CONTEXT_CLIENT.getSSLContext(uri, authenticationContext);
        } catch (GeneralSecurityException e) {
            throw new WildflyClientConfigException();
        }
    }

    public String getUsername(URI uri) throws WildflyClientConfigException {
        final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
        NameCallback nameCallback = new NameCallback("user name");
        try {
            callbackHandler.handle(new Callback[]{nameCallback});
            return nameCallback.getName();
        } catch (IOException | UnsupportedCallbackException e) {
            throw new WildflyClientConfigException();
        }
    }

    public String getPassword(URI uri) throws WildflyClientConfigException {
        final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        try {
            callbackHandler.handle(new Callback[]{passwordCallback});
            char[] password = passwordCallback.getPassword();
            if (password == null) {
                return null;
            }
            return new String(password);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new WildflyClientConfigException();
        }
    }
}
