



package com.portal.customStorage.provider;

import com.portal.customStorage.model.Customer;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class CustomerAdapter extends AbstractUserAdapterFederatedStorage implements CredentialInputValidator {

    private final Customer customer;
    private final ComponentModel storageProviderModel;

    public CustomerAdapter(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel, Customer customer) {
        super(session, realm, storageProviderModel);
        this.customer = customer;
        this.storageProviderModel = storageProviderModel;
    }

    @Override
    public String getId() {
        if (storageId == null) {
            storageId = new StorageId(storageProviderModel.getId(), String.valueOf(customer.getId()));
        }
        return storageId.getId();
    }

    /* --- Overriding Internal Attribute Engines to Render UI Dashboards --- */
//    @Override
//    public String getFirstAttribute(String name) {
//        if (UserModel.FIRST_NAME.equals(name)) {
//            return customer.getFirstName();
//        } else if (UserModel.LAST_NAME.equals(name)) {
//            return customer.getLastName();
//        } else if (UserModel.EMAIL.equals(name)) {
//            return customer.getEmail();
//        }
//        return super.getFirstAttribute(name);
//    }

    @Override
    public String getFirstAttribute(String name) {
        if (UserModel.FIRST_NAME.equals(name)) {
            return customer.getFirstName();
        } else if (UserModel.LAST_NAME.equals(name)) {
            return customer.getLastName();
        } else if (UserModel.EMAIL.equals(name)) {
            return customer.getEmail();
        } else if ("password".equalsIgnoreCase(name)) { // FIXED: Exposes password securely to the proxy evaluation context
            return customer.getPassword();
        }
        return super.getFirstAttribute(name);
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        // FIXED: Wrap in a new HashMap to handle mutable data mutations safely
        Map<String, List<String>> attrs = new java.util.HashMap<>(super.getAttributes());

        attrs.put(UserModel.FIRST_NAME, Collections.singletonList(customer.getFirstName()));
        attrs.put(UserModel.LAST_NAME, Collections.singletonList(customer.getLastName()));
        attrs.put(UserModel.EMAIL, Collections.singletonList(customer.getEmail()));
        return attrs;
    }


    /* --- Core Getters and Setters for standard mappings --- */
    public String getPassword() {
        return customer.getPassword();
    }

    @Override
    public String getUsername() {
        return customer.getUserName();
    }

    @Override
    public void setUsername(String username) {
        // Read-only bridge layer configuration
    }

    @Override
    public String getEmail() {
        return customer.getEmail();
    }

    @Override
    public String getFirstName() {
        return customer.getFirstName();
    }

    @Override
    public String getLastName() {
        return customer.getLastName();
    }

    @Override
    public boolean isEnabled() {
        // Converts the integer value to a boolean condition (returns true if active is 1)
        return customer.getActive() == 1;
    }
    /* --- FIXED: Credential Validator Compliance Methods Complete Layout --- */
    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        // Core engine defaults execution workflow back to CustomerStorageProvider's validation block
        return false;
    }
}
