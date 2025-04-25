package io.krystof.keycloak.social.twitch;

import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Username mapper for Twitch identity provider.
 * This mapper allows Keycloak administrators to configure how usernames are generated
 * from Twitch profile data.
 */
public class TwitchUsernameMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "twitch-username-mapper";
    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private static final String[] COMPATIBLE_PROVIDERS = {TwitchIdentityProviderFactory.PROVIDER_ID};

    public static final String TEMPLATE = "template";

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(TEMPLATE);
        property.setLabel("Template");
        property.setHelpText("Template to create the username. You can use ${email}, ${sub}, or any other Twitch profile attribute like ${email_verified}, ${picture}, ${aud}, ${exp}, ${iat}, ${iss}. Default is ${email}.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("${email}");
        configProperties.add(property);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Twitch Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Twitch Username";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getHelpText() {
        return "Format the username based on a template using Twitch profile attributes.";
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String template = mapperModel.getConfig().get(TEMPLATE);
        if (template == null) {
            template = "${email}";
        }

        String username = formatUsername(template, context);
        if (username != null && !username.isEmpty()) {
            user.setUsername(username);
        }
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        // We don't update the username on subsequent logins
    }
    
    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        // No preprocessing needed
    }
    
    @Override
    public void updateBrokeredUserLegacy(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        // No legacy update needed
    }

    private String formatUsername(String template, BrokeredIdentityContext context) {
        Map<String, Object> attributes = context.getContextData();
        String result = template;

        // Replace known attributes
        if (context.getEmail() != null) {
            result = result.replace("${email}", context.getEmail());
        }
        if (context.getId() != null) {
            result = result.replace("${sub}", context.getId());
        }
        if (context.getUsername() != null) {
            result = result.replace("${username}", context.getUsername());
        }

        // Replace other attributes from the context data
        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
            if (entry.getValue() instanceof String) {
                result = result.replace("${" + entry.getKey() + "}", (String) entry.getValue());
            }
        }

        // Replace any remaining placeholders with empty strings
        result = result.replaceAll("\\$\\{[^}]+\\}", "");

        return result;
    }
}
