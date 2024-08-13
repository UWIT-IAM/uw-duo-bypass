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

import java.util.ArrayList;
import java.util.function.Function;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import javax.security.auth.Subject;
import jakarta.servlet.ServletRequest;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;


import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext;
import edu.washington.idp.authn.duobypass.DuoBypassPrincipal;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.FunctionSupport;

import net.shibboleth.idp.profile.context.SpringRequestContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// import com.google.common.base.Function;

/**
 * An action that validates a DuoBypass response token and produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} or records error state.
 *
 * <p>The username to cross-check comes from a lookup strategy, by default a {@link CanonicalUsernameLookupStrategy}
 * that returns a username produced by an earlier authentication flow, and on success the same name is populated into
 * a {@link SubjectCanonicalizationContext} as a pre-established result for the login flow.
 *
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @post ProfileRequestContext.getSubcontext(SubjectCanonicalizationContext.class).getPrincipalName() != null
 *
 */
public class ValidateDuoBypass extends AbstractValidationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateDuoBypass.class);

    /** Lookup strategy for username to match against DupBypass identity. */
    @Nonnull private Function<ProfileRequestContext,String> usernameLookupStrategy;

    /** Attempted username. */
    @Nullable @NotEmpty private String username;

    /** Constructor. */
    public ValidateDuoBypass() {
        usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
    }

    /**
     * Set the lookup strategy to use for the prepopulated username
     *
     * @param strategy lookup strategy
     */
    public void setUsernameLookupStrategy(@Nonnull final Function<ProfileRequestContext,String> strategy) {
        this.ifInitializedThrowUnmodifiabledComponentException();

        usernameLookupStrategy = Constraint.isNotNull(strategy, "Username lookup strategy cannot be null");
    }


    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }

        username = usernameLookupStrategy.apply(profileRequestContext);
        if (username == null) {
            log.warn("{} No principal name available to check DuoBypass result", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }

        final ServletRequest servletRequest = getHttpServletRequest();
        if (servletRequest == null) {
            log.error("{} No ServletRequest available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            recordFailure(profileRequestContext);
            return false;
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {


        log.info("DuoBypass authentication succeeded for '{}'", username);
        recordSuccess(profileRequestContext);
        buildAuthenticationResult(profileRequestContext, authenticationContext);

    }

    /** {@inheritDoc} */
    @Override
    protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new DuoBypassPrincipal(username));
        return subject;
    }

    /** {@inheritDoc} */
    @Override
    protected void buildAuthenticationResult(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        super.buildAuthenticationResult(profileRequestContext, authenticationContext);

        // Bypass c14n. We already operate on a canonical name, so just re-confirm it.
        profileRequestContext.getSubcontext(SubjectCanonicalizationContext.class, true).setPrincipalName(username);
    }



}

