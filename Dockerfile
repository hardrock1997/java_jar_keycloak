FROM quay.io/keycloak/keycloak:26.1.0

COPY build/libs/*.jar /opt/keycloak/providers/

# FIXED: Instructs Quarkus to forcefully bypass and ignore ghost persistence.xml files on the classpath
ENV QUARKUS_HIBERNATE_ORM_PERSISTENCE_XML_IGNORE=true

# The environment variable is read during this build step
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--spi-connections-jpa-default-quarkus-hibernate-orm-persistence-xml-ignore=true"]

