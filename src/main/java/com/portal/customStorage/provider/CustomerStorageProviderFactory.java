package com.portal.customStorage.provider;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;

public class CustomerStorageProviderFactory implements UserStorageProviderFactory<CustomerStorageProvider> {

    @Override
    public CustomerStorageProvider create(KeycloakSession keycloakSession, ComponentModel componentModel) {
        try {
            String dbUrl = componentModel.getConfig().getFirst("dbUrl");
            String dbUser = componentModel.getConfig().getFirst("dbUser");
            String dbPassword = componentModel.getConfig().getFirst("dbPassword");

            if (dbUrl == null || dbUrl.trim().isEmpty()) {
                dbUrl = "jdbc:mysql://host.docker.internal:3306/customer?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC";
            }
            if (dbUser == null || dbUser.trim().isEmpty()) {
                dbUser = "root";
            }
            if (dbPassword == null || dbPassword.trim().isEmpty()) {
                dbPassword = "yash@260397";
            }

            // Bypasses Quarkus classloader encapsulation boundaries safely
            Connection connection;
            try {
                Class.forName("com.mysql.cj.jdbc.Driver", true, CustomerStorageProviderFactory.class.getClassLoader());
                connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
            } catch (Exception ex) {
                // Fallback registry option for container runtimes
                DriverManager.registerDriver(new com.mysql.cj.jdbc.Driver());
                connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
            }

            // FIXED: Uses the 3-argument constructor to match your compiled CustomerStorageProvider layout perfectly
            return new CustomerStorageProvider(keycloakSession, componentModel, connection);
        } catch (Exception e) {
            throw new RuntimeException("Failed to open native isolated JDBC connection link", e);
        }
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("dbUrl")
                .label("Database JDBC URL")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("jdbc:mysql://host.docker.internal:3306/customer?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC")
                .add()
                .property()
                .name("dbUser")
                .label("Database Username")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("root")
                .add()
                .property()
                .name("dbPassword")
                .label("Database Password")
                .type(ProviderConfigProperty.PASSWORD)
                .defaultValue("")
                .add()
                .build();
    }

    @Override
    public String getId() {
        return "Custom-user-storage";
    }
}
