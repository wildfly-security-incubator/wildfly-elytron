/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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
 */
package org.wildfly.security.http.digest;

import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

import java.io.Serializable;

/**
 * Interface for utilities responsible for managing nonces
 */
public interface NonceManager extends Serializable {

    /**
     * Generate a new encoded nonce to send to the client.
     *
     * @param salt additional data to use when creating the overall signature for the nonce.
     * @return a new encoded nonce to send to the client.
     */
    String generateNonce(byte[] salt);

    /**
     * Attempt to use the supplied nonce.
     *
     * A nonce might not be usable for a couple of different reasons: -
     *
     * <ul>
     *     <li>It was created too far in the past.
     *     <li>Validation of the signature fails.
     *     <li>The nonce has been used previously and re-use is disabled.
     * </ul>
     *
     * @param nonce the nonce supplied by the client.
     * @param salt additional data to use when creating the overall signature for the nonce.
     * @return {@code true} if the nonce can be used, {@code false} otherwise.
     * @throws AuthenticationMechanismException
     */
    boolean useNonce(String nonce, byte[] salt, int nonceCount) throws AuthenticationMechanismException;

    /**
     * Clean up and shut down the NonceManager
     */
    void shutdown();

    /**
     * Set the HTTP server request that is currently being evaluated
     * @param request
     */
    void setRequest(HttpServerRequest request);

    /**
     * @return HTTP server request that is currently being evaluated by the nonce manager
     */
    HttpServerRequest getRequest();

    /**
     * @return whether this nonce manager is being persisted in a session
     */
    boolean persistToSession();
}
