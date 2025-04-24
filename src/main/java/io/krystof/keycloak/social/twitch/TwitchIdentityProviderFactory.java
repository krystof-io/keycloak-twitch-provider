package io.krystof.keycloak.social.twitch;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Factory for creating instances of the Twitch Identity Provider
 */
public class TwitchIdentityProviderFactory extends AbstractIdentityProviderFactory<TwitchIdentityProvider>
        implements SocialIdentityProviderFactory<TwitchIdentityProvider> {

    public static final String PROVIDER_ID = "twitch";

    @Override
    public String getName() {
        return "Twitch";
    }

    @Override
    public TwitchIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new TwitchIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}