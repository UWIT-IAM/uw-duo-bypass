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

package edu.washington.idp.authn.duobypass;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.principal.CloneablePrincipal;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import com.google.common.base.MoreObjects;

/** Principal from an DuoBypass authentication. */
public class DuoBypassPrincipal implements CloneablePrincipal {

    @Nonnull @NotEmpty private String username;

    public DuoBypassPrincipal(@Nonnull @NotEmpty @ParameterName(name="name") final String name) {
        username = Constraint.isNotNull(StringSupport.trimOrNull(name), "Username cannot be null or empty");
    }

    @Override
    @Nonnull @NotEmpty public String getName() {
        return username;
    }

    @Override
    public boolean equals(final Object other) {
        if (other == null) {
            return false;
        }

        if (this == other) {
            return true;
        }

        if (other instanceof DuoBypassPrincipal) {
            return username.equals(((DuoBypassPrincipal) other).getName());
        }

        return false;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).add("username", username).toString();
    }

    @Override
    public DuoBypassPrincipal clone() throws CloneNotSupportedException {
        final DuoBypassPrincipal copy = (DuoBypassPrincipal) super.clone();
        copy.username = username;
        return copy;
    }
}

