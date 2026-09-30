package com.portal.customStorage.provider;

import com.portal.customStorage.model.Customer;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.mindrot.jbcrypt.BCrypt;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class CustomerStorageProvider implements UserStorageProvider,
        UserQueryProvider,
        UserLookupProvider,
        CredentialInputValidator {

    private ComponentModel componentModel;
    private KeycloakSession keycloakSession;
    private Connection connection;
    private static final Logger logger = Logger.getLogger(CustomerStorageProvider.class);


    // Explicit 3-argument constructor to match your factory logic
    public CustomerStorageProvider(KeycloakSession keycloakSession, ComponentModel componentModel, Connection connection) {
        this.keycloakSession = keycloakSession;
        this.componentModel = componentModel;
        this.connection = connection;
    }

    // Retained setters to keep backwards-compatibility intact
    public void setModel(ComponentModel componentModel) { this.componentModel = componentModel; }
    public void setSession(KeycloakSession keycloakSession) { this.keycloakSession = keycloakSession; }
    public void setConnection(Connection connection) { this.connection = connection; }

    @Override
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /* --- Credential Input Validator Engine --- */
    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }


public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
    // 1. Instantly exit if this isn't a password check
    if (!supportsCredentialType(credentialInput.getType())) {
        return false;
    }

    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(CustomerStorageProvider.class);
    String inputPlainTextPassword = credentialInput.getChallengeResponse();
    String databasePasswordHash = null;

    // 2. Safely parse out the raw MySQL primary key (Long ID) from Keycloak's unique string identifier
    String externalId = org.keycloak.storage.StorageId.externalId(user.getId());
    logger.infof("[DEBUG-SPI] Evaluating credentials for user: %s (MySQL Primary Key ID: %s)", user.getUsername(), externalId);

    // 3. Make a direct query to the isolated DB connection context to grab the credentials row
    String sql = "SELECT password FROM customer WHERE id = ?";
    try (PreparedStatement statement = connection.prepareStatement(sql)) {
        statement.setLong(1, Long.parseLong(externalId));
        try (ResultSet resultSet = statement.executeQuery()) {
            if (resultSet.next()) {
                databasePasswordHash = resultSet.getString("password");
            }
        }
    } catch (Exception e) {
        logger.errorf("[DEBUG-SPI] Failed to extract password hash from database engine target: %s", e.getMessage());
    }

    logger.infof("[DEBUG-SPI] Input Password Typed: %s", inputPlainTextPassword);
    logger.infof("[DEBUG-SPI] DB Password Extracted: %s", databasePasswordHash);

    // 4. CRITICAL NPE PROTECTION: Immediately drop out if either field is null BEFORE any string operations run
    if (databasePasswordHash == null || inputPlainTextPassword == null) {
        logger.error("[DEBUG-SPI] Validation dropped: One of the password parameters is null!");
        return false;
    }

    // 5. Clean up any whitespaces or trailing character blocks safely
    databasePasswordHash = databasePasswordHash.trim();
    inputPlainTextPassword = inputPlainTextPassword.trim();

    // 6. Direct Local Development Match Fallback (Plain Text Evaluation)
    if (inputPlainTextPassword.equals(databasePasswordHash)) {
        logger.info("[DEBUG-SPI] Match Success: Passwords match via Plain-Text check!");
        return true;
    }

    // 7. Standard BCrypt Matching Core (Supports standard $2a$, $2b$, and modern $2y$ salt layouts safely)
    try {
        if (databasePasswordHash.startsWith("$2a$") ||
                databasePasswordHash.startsWith("$2b$") ||
                databasePasswordHash.startsWith("$2y$")) {

            boolean matches = BCrypt.checkpw(inputPlainTextPassword, databasePasswordHash);
            logger.infof("[DEBUG-SPI] BCrypt Matching Evaluation Result: %b", matches);
            return matches;
        } else {
            logger.warnf("[DEBUG-SPI] DB Hash [%s] does not look like a standard BCrypt string format.", databasePasswordHash);
        }
    } catch (Exception e) {
        logger.errorf("[DEBUG-SPI] Exception thrown during BCrypt hashing operation: %s", e.getMessage());
    }

    return false;
}

    /* --- User Lookup Engine --- */
    @Override
    public UserModel getUserByUsername(RealmModel realmModel, String userName) {
        String sql = "SELECT id, username, email, first_name, last_name, active, password FROM customer WHERE username = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, userName);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return mapResultSetToUser(realmModel, resultSet);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public UserModel getUserById(RealmModel realmModel, String id) {
        String externalId = StorageId.externalId(id);
        String sql = "SELECT id, username, email, first_name, last_name, active, password FROM customer WHERE id = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, Long.parseLong(externalId));
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return mapResultSetToUser(realmModel, resultSet);
                }
            }
        } catch (Exception e) {
            // Fall through gracefully
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realmModel, String email) {
        String sql = "SELECT id, username, email, first_name, last_name, active, password FROM customer WHERE email = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, email);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return mapResultSetToUser(realmModel, resultSet);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /* --- User Query Engine --- */
    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> map, Integer firstResult, Integer maxResults) {
        String searchParam = map.getOrDefault(UserModel.SEARCH,
                map.getOrDefault(UserModel.USERNAME,
                        map.getOrDefault(UserModel.EMAIL, "")));

        String sql = "SELECT id, username, email, first_name, last_name, active, password FROM customer WHERE username LIKE ? OR email LIKE ? LIMIT ? OFFSET ?";

        List<UserModel> users = new ArrayList<>();
        int limit = (maxResults != null && maxResults > 0) ? maxResults : 100;
        int offset = (firstResult != null && firstResult >= 0) ? firstResult : 0;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, "%" + searchParam + "%");
            statement.setString(2, "%" + searchParam + "%");
            statement.setInt(3, limit);
            statement.setInt(4, offset);

            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    users.add(mapResultSetToUser(realmModel, resultSet));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return users.stream();
    }

    // FIXED: Fully safely closed out the truncated execution blocks
    @Override
    public int getUsersCount(RealmModel realm) {
        String sql = "SELECT COUNT(*) FROM customer";
        try (PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet resultSet = statement.executeQuery()) {
            if (resultSet.next()) {
                return resultSet.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    // FIXED: Maps the ResultSet via getInt("active") to align with your model properties configuration
    private UserModel mapResultSetToUser(RealmModel realmModel, ResultSet resultSet) throws SQLException {
        Customer customer = new Customer();
        customer.setId(resultSet.getLong("id"));
        customer.setUserName(resultSet.getString("username"));
        customer.setEmail(resultSet.getString("email"));
        customer.setFirstName(resultSet.getString("first_name"));
        customer.setLastName(resultSet.getString("last_name"));
        customer.setActive(resultSet.getInt("active")); // Extracts integer correctly matching model
        customer.setPassword(resultSet.getString("password"));

        return new CustomerAdapter(keycloakSession, realmModel, componentModel, customer);
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }
}
