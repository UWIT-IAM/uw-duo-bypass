/* ========================================================================
 * Copyright (c) 2016 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

package edu.washington.idp.authn.duobypass.impl;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Principal;
import java.util.regex.Pattern;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonStructure;
import jakarta.json.stream.JsonGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

import edu.washington.idp.authn.duobypass.DuoBypassPrincipal;
import net.shibboleth.idp.authn.principal.AbstractPrincipalSerializer;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Principal serializer for {@link DuoBypassPrincipal}.
 */
@ThreadSafe
public class DuoBypassPrincipalSerializer extends AbstractPrincipalSerializer<String> {

    /** Field name of {@link DuoBypassPrincipal}. */
    @Nonnull @NotEmpty private static final String ENTRUST_FIELD = "Entrust";

    /** Pattern used to determine if input is supported. */
    @Nonnull private static final Pattern JSON_PATTERN = Pattern.compile("^\\{\"Entrust\":.*\\}$");

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(DuoBypassPrincipalSerializer.class);

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull final Principal principal) {
        return principal instanceof DuoBypassPrincipal;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull @NotEmpty public String serialize(@Nonnull final Principal principal) throws IOException {
        final StringWriter sink = new StringWriter(32);
        final JsonGenerator gen = getJsonGenerator(sink);
        gen.writeStartObject()
            .write(ENTRUST_FIELD, principal.getName())
            .writeEnd();
        gen.close();
        return sink.toString();
    }

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull @NotEmpty final String value) {
        return JSON_PATTERN.matcher(value).matches();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public DuoBypassPrincipal deserialize(@Nonnull @NotEmpty final String value) throws IOException {
        final JsonReader reader = getJsonReader(new StringReader(value));
        JsonStructure st = null;
        try {
            st = reader.read();
        } finally {
            reader.close();
        }
        if (!(st instanceof JsonObject)) {
            throw new IOException("Found invalid data structure while parsing DuoBypassPrincipal");
        }
        final JsonString str = ((JsonObject) st).getJsonString(ENTRUST_FIELD);
        if (str != null) {
            final String username = str.getString();
            if (!Strings.isNullOrEmpty(username)) {
                return new DuoBypassPrincipal(username);
            }
        }
        return null;
    }
}
