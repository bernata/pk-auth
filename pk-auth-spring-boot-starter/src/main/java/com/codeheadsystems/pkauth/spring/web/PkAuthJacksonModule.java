// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.web;

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
import java.io.IOException;

/**
 * Jackson 2 mirror of {@link com.codeheadsystems.pkauth.json.PkAuthObjectMappers}'s module. The
 * core ships a Jackson 3 module; Spring MVC still uses Jackson 2 in its {@code
 * MappingJackson2HttpMessageConverter}, so we register the same wire conventions here:
 *
 * <ul>
 *   <li>{@code byte[]} ↔ base64url string (RFC 4648 §5, no padding).
 *   <li>{@link UserHandle} ↔ base64url string of its bytes.
 *   <li>{@link ChallengeId} ↔ its plain string value.
 * </ul>
 *
 * <p>Without this module Spring would default to {@code byte[]} ↔ base64 with padding (RFC 4648
 * §4), and the wire format would diverge from the Jackson 3 mapper used by tests and clients.
 */
public final class PkAuthJacksonModule extends SimpleModule {

  private static final long serialVersionUID = 1L;

  public PkAuthJacksonModule() {
    super("pk-auth");
    addSerializer(byte[].class, new Base64UrlBytesSerializer());
    addDeserializer(byte[].class, new Base64UrlBytesDeserializer());
    addSerializer(UserHandle.class, new UserHandleSerializer());
    addDeserializer(UserHandle.class, new UserHandleDeserializer());
    addSerializer(ChallengeId.class, new ChallengeIdSerializer());
    addDeserializer(ChallengeId.class, new ChallengeIdDeserializer());
  }

  private static final class Base64UrlBytesSerializer extends JsonSerializer<byte[]> {
    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializerProvider serializers)
        throws IOException {
      gen.writeString(Base64Url.encode(value));
    }
  }

  private static final class Base64UrlBytesDeserializer extends JsonDeserializer<byte[]> {
    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      String text = p.getValueAsString();
      if (text == null || text.isEmpty()) {
        return new byte[0];
      }
      return Base64Url.decode(text);
    }
  }

  private static final class UserHandleSerializer extends JsonSerializer<UserHandle> {
    @Override
    public void serialize(UserHandle value, JsonGenerator gen, SerializerProvider serializers)
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
    public void serialize(ChallengeId value, JsonGenerator gen, SerializerProvider serializers)
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
