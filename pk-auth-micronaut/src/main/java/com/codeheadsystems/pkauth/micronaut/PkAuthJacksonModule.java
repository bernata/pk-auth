// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.micronaut.context.annotation.Factory;
import jakarta.inject.Singleton;
import java.io.IOException;

/**
 * Teaches Micronaut's Jackson 2 {@code ObjectMapper} to read and write the pk-auth wire types.
 * pk-auth-core uses Jackson 3 (ADR 0009); Micronaut still ships Jackson 2 internally. Providing
 * this {@link SimpleModule} as a Micronaut bean makes the framework's mapper produce the same
 * base64url-encoded byte[] / UserHandle / ChallengeId wire shapes the core's mapper produces.
 */
@Factory
public class PkAuthJacksonModule {

  @Singleton
  SimpleModule pkAuthModule() {
    SimpleModule m = new SimpleModule("pk-auth-micronaut");
    m.addSerializer(byte[].class, new BytesSerializer());
    m.addDeserializer(byte[].class, new BytesDeserializer());
    m.addSerializer(UserHandle.class, new UserHandleSerializer());
    m.addDeserializer(UserHandle.class, new UserHandleDeserializer());
    m.addSerializer(ChallengeId.class, new ChallengeIdSerializer());
    m.addDeserializer(ChallengeId.class, new ChallengeIdDeserializer());
    return m;
  }

  private static final class BytesSerializer extends JsonSerializer<byte[]> {
    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializerProvider provider)
        throws IOException {
      gen.writeString(Base64Url.encode(value));
    }
  }

  private static final class BytesDeserializer extends JsonDeserializer<byte[]> {
    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      String s = p.getValueAsString();
      return s == null ? new byte[0] : Base64Url.decode(s);
    }
  }

  private static final class UserHandleSerializer extends JsonSerializer<UserHandle> {
    @Override
    public void serialize(UserHandle value, JsonGenerator gen, SerializerProvider provider)
        throws IOException {
      gen.writeString(Base64Url.encode(value.value()));
    }
  }

  private static final class UserHandleDeserializer extends JsonDeserializer<UserHandle> {
    @Override
    public UserHandle deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      return new UserHandle(Base64Url.decode(p.getValueAsString()));
    }
  }

  private static final class ChallengeIdSerializer extends JsonSerializer<ChallengeId> {
    @Override
    public void serialize(ChallengeId value, JsonGenerator gen, SerializerProvider provider)
        throws IOException {
      gen.writeString(value.value());
    }
  }

  private static final class ChallengeIdDeserializer extends JsonDeserializer<ChallengeId> {
    @Override
    public ChallengeId deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      return new ChallengeId(p.getValueAsString());
    }
  }
}
