package io.krystof.keycloak.social.twitch;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * User attribute mapper for Twitch identity provider.
 * This mapper allows Keycloak administrators to map attributes from the Twitch profile
 * to Keycloak user attributes through the admin console.
 */
public class TwitchUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    private static final String[] COMPATIBLE_PROVIDERS = new String[] { TwitchIdentityProviderFactory.PROVIDER_ID };
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String TWITCH_USER_ATTRIBUTE = "twitch.user.attribute";
    private static final String TWITCH_ATTRIBUTE_HELP_TEXT = "Available Twitch profile attributes: sub, email, email_verified, picture, aud, exp, iat, iss";

    // Constants from AbstractJsonUserAttributeMapper
    public static final String ATTRIBUTE_NAME = "jsonField";
    public static final String USER_ATTRIBUTE = "userAttribute";
    
    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_NAME);
        property.setLabel("Attribute Name");
        property.setHelpText("Name of the attribute to search for in the Twitch profile JSON. " + TWITCH_ATTRIBUTE_HELP_TEXT);
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(USER_ATTRIBUTE);
        property.setLabel("User Attribute Name");
        property.setHelpText("Name of the user attribute to store the Twitch profile attribute value.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getId() {
        return "twitch-user-attribute-mapper";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return "Twitch Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Twitch User Attribute Mapper";
    }

    @Override
    public String getHelpText() {
        return "Maps attributes from the Twitch profile to user attributes. " + TWITCH_ATTRIBUTE_HELP_TEXT;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        super.importNewUser(session, realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        super.updateBrokeredUser(session, realm, user, mapperModel, context);
    }
}
