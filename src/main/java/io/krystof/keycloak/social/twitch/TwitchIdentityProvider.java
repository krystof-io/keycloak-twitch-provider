package io.krystof.keycloak.social.twitch;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Twitch Identity Provider implementation for Keycloak
 * This implementation handles Twitch's specific requirements for OpenID Connect,
 * particularly the need to specifically request email claims and convert scope arrays to strings.
 */
public class TwitchIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(TwitchIdentityProvider.class);
    
    public static final String AUTH_URL = "https://id.twitch.tv/oauth2/authorize";
    public static final String TOKEN_URL = "https://id.twitch.tv/oauth2/token";
    public static final String PROFILE_URL = "https://id.twitch.tv/oauth2/userinfo";
    public static final String DEFAULT_SCOPE = "openid user:read:email";

    public TwitchIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        
        // Set default endpoints if they're not configured
        if (config.getAuthorizationUrl() == null || config.getAuthorizationUrl().isEmpty()) {
            config.setAuthorizationUrl(AUTH_URL);
        }
        if (config.getTokenUrl() == null || config.getTokenUrl().isEmpty()) {
            config.setTokenUrl(TOKEN_URL);
        }
        if (config.getUserInfoUrl() == null || config.getUserInfoUrl().isEmpty()) {
            config.setUserInfoUrl(PROFILE_URL);
        }
        
        // Ensure we have the required scopes
        if (config.getDefaultScope() == null || config.getDefaultScope().isEmpty()) {
            config.setDefaultScope(DEFAULT_SCOPE);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }
    
    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        logger.infof("Creating authorization URL for Twitch provider. State: %s, Redirect URI: %s", 
                     request.getState().getEncoded(), request.getRedirectUri());
        
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        logger.debugf("Base authorization URL from parent: %s", uriBuilder.build().toString());
        
        // Add Twitch-specific claims parameter for requesting email
        try {
            String claimsJson = "{id_token:{email:null,email_verified:null,picture:null,preferred_username:null},userinfo:{email:null,email_verified:null,picture:null,preferred_username:null}}";
            String encodedClaims = URLEncoder.encode(claimsJson, StandardCharsets.UTF_8.toString());
            
            logger.infof("Adding claims parameter to Twitch authorization URL");
            UriBuilder finalBuilder = uriBuilder.queryParam("claims", encodedClaims);
            logger.debugf("Final Twitch authorization URL: %s", finalBuilder.build().toString());
            
            return finalBuilder;
        } catch (Exception e) {
            logger.errorf(e, "Error creating authorization URL for Twitch provider");
            throw new IdentityBrokerException("Could not create authorization URL for Twitch provider", e);
        }
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        logger.infof("Authenticating token request to: %s", tokenRequest.getUrl());
        return super.authenticateTokenRequest(tokenRequest);
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        logger.infof("Extracting identity from Twitch profile");
        logger.debugf("Raw profile data: %s", profile.toString());
        
        String subjectId = getJsonProperty(profile, "sub");
        logger.infof("Subject ID from profile: %s", subjectId);
        
        BrokeredIdentityContext user = new BrokeredIdentityContext(subjectId, getConfig());

        // Set mandatory fields
        String username = getJsonProperty(profile, "preferred_username");
        logger.infof("Username from profile: %s", username);
        user.setUsername(username);
        user.setIdp(this);

        // Set optional fields if available
        String email = getJsonProperty(profile, "email");
        if (email != null) {
            logger.infof("Email from profile: %s", email);
            user.setEmail(email);
            
            // Set email verification status if available
            Boolean emailVerified = getBooleanProperty(profile, "email_verified");
            if (emailVerified != null) {
                logger.infof("Email verified status: %s", emailVerified);
                user.setUserAttribute("email_verified", emailVerified.toString());
            }
        } else {
            logger.infof("No email found in profile");
        }

        // Add profile picture if available
        String picture = getJsonProperty(profile, "picture");
        if (picture != null) {
            logger.infof("Profile picture URL found");
            user.setUserAttribute("picture", picture);
        }

        // Add all available profile data as attributes
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        logger.infof("Completed extracting identity from Twitch profile");

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        // Mask most of the token for logging
        String maskedToken = "...";
        if (accessToken != null && accessToken.length() > 8) {
            maskedToken = accessToken.substring(0, 4) + "..." + accessToken.substring(accessToken.length() - 4);
        }
        logger.infof("Getting federated identity from Twitch with access token: %s", maskedToken);
        
        try {
            logger.debugf("Calling Twitch userinfo endpoint: %s", getConfig().getUserInfoUrl());
            JsonNode profile = SimpleHttp.doGet(getConfig().getUserInfoUrl(), session)
                .header("Authorization", "Bearer " + accessToken)
                .asJson();
            
            logger.infof("Successfully retrieved profile from Twitch");
            return extractIdentityFromProfile(null, profile);
        } catch (IOException e) {
            logger.errorf(e, "Failed to obtain user profile from Twitch");
            throw new IdentityBrokerException("Could not obtain user profile from Twitch", e);
        }
    }
    
    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        logger.infof("Processing OAuth token response from Twitch");
        logger.debugf("Raw token response: %s", response);
        
        String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
        
        // Mask most of the token for logging
        String maskedToken = "...";
        if (accessToken != null && accessToken.length() > 8) {
            maskedToken = accessToken.substring(0, 4) + "..." + accessToken.substring(accessToken.length() - 4);
        }
        
        if (accessToken == null) {
            logger.errorf("No access token found in response");
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        } else {
            logger.infof("Access token extracted: %s", maskedToken);
        }

        // Handle Twitch's response with scope as an array instead of a space-separated string
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode node = objectMapper.readTree(response);
            
            logger.debugf("Token response as JSON: %s", node.toString());
            
            // Check if scope is an array and convert it to a space-separated string
            if (node.has("scope")) {
                logger.infof("Scope found in token response");
                if (node.get("scope").isArray()) {
                    logger.infof("Scope is an array, converting to string");
                    String scopeString = convertScopeArrayToString(node.get("scope"));
                    ((ObjectNode) node).put("scope", scopeString);
                    
                    logger.infof("Converted scope array to string: %s", scopeString);
                    
                    // Convert the modified node back to a string for further processing
                    response = objectMapper.writeValueAsString(node);
                    logger.debugf("Modified token response: %s", response);
                    
                    // Re-extract the access token in case it was modified
                    accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
                    logger.infof("Re-extracted access token after scope conversion: %s", maskedToken);
                } else {
                    logger.infof("Scope is already a string: %s", node.get("scope").asText());
                }
            } else {
                logger.infof("No scope found in token response");
            }
        } catch (IOException e) {
            logger.errorf(e, "Error parsing token response");
            // Continue with the original response if there's an error
        }

        logger.infof("Getting federated identity with access token");
        BrokeredIdentityContext context = doGetFederatedIdentity(accessToken);
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        logger.infof("Successfully created brokered identity context");
        
        return context;
    }
    
    /**
     * Converts a JSON array of scopes to a space-separated string
     */
    private String convertScopeArrayToString(JsonNode scopeArray) {
        if (!scopeArray.isArray()) {
            return scopeArray.asText();
        }
        
        List<String> scopes = new ArrayList<>();
        for (Iterator<JsonNode> it = scopeArray.elements(); it.hasNext();) {
            scopes.add(it.next().asText());
        }
        
        if (scopes.isEmpty()) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < scopes.size() - 1; i++) {
            sb.append(scopes.get(i)).append(" ");
        }
        sb.append(scopes.get(scopes.size() - 1));
        
        return sb.toString();
    }
    
    // Helper method to extract boolean properties from JSON
    private Boolean getBooleanProperty(JsonNode jsonNode, String name) {
        if (jsonNode.has(name) && !jsonNode.get(name).isNull()) {
            return jsonNode.get(name).asBoolean();
        }
        return null;
    }
}
