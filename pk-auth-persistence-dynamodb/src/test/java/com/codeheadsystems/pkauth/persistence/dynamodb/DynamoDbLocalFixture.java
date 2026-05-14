// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import java.net.URI;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

/** Shared Testcontainers dynamodb-local fixture started once per JVM. */
public final class DynamoDbLocalFixture {

  @SuppressWarnings("resource")
  private static final GenericContainer<?> CONTAINER =
      new GenericContainer<>(DockerImageName.parse("amazon/dynamodb-local:latest"))
          .withExposedPorts(8000)
          .withReuse(true);

  private static DynamoDbClient client;
  private static DynamoDbEnhancedClient enhanced;

  private DynamoDbLocalFixture() {}

  /** Lazily starts the container and returns the low-level client. */
  public static synchronized DynamoDbClient client() {
    if (client != null) {
      return client;
    }
    if (!CONTAINER.isRunning()) {
      CONTAINER.start();
    }
    String endpoint = "http://localhost:" + CONTAINER.getMappedPort(8000);
    client =
        DynamoDbClient.builder()
            .endpointOverride(URI.create(endpoint))
            .region(Region.US_EAST_1)
            .credentialsProvider(
                StaticCredentialsProvider.create(AwsBasicCredentials.create("fake", "fake")))
            .build();
    enhanced = DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
    return client;
  }

  /** Returns the enhanced client for the started container. */
  public static synchronized DynamoDbEnhancedClient enhanced() {
    client();
    return enhanced;
  }
}
