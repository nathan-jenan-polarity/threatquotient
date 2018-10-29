'use strict';

let request = require('request');
let util = require('util');
let net = require('net');
let config = require('./config/config');
let { Address6 } = require('ip-address');
let async = require('async');
let fs = require('fs');
let SessionManager = require('./lib/session-manager');
let Logger;

let requestWithDefaults;
let sessionManager;


//process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const IGNORED_IPS = new Set([
    '127.0.0.1',
    '255.255.255.255',
    '0.0.0.0'
]);

const ERROR_EXPIRED_SESSION = 'expired_session_error';
const MAX_ENTITIES_PER_LOOKUP = 1;

function createEntityGroups(entities, options, cb) {
    let entityLookup = {};
    let entityGroups = [];
    let entityGroup = [];

    Logger.debug({ entities: entities, options: options }, 'Entities and Options');

    entities.forEach(function (entity) {
        if (entityGroup.length >= MAX_ENTITIES_PER_LOOKUP) {
            entityGroups.push(entityGroup);
            entityGroup = [];
        }

        if (((entity.isPrivateIP || IGNORED_IPS.has(entity.value)) && options.ignorePrivateIps) ||
            (entity.isIPv6 && !new Address6(entity.value).isValid()) || entity.types.indexOf('custom.cidr') > 0) {
            return;
        } else {
            entityGroup.push(entity.value);
            entityLookup[entity.value.toLowerCase()] = entity;
        }
    });

    // grab any "trailing" entities
    if (entityGroup.length > 0) {
        entityGroups.push(entityGroup);
    }

    Logger.trace({ entityGroups: entityGroups }, 'Entity Groups');

    _doLookup(entityGroups, entityLookup, options, cb);
}

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function _doLookup(entityGroups, entityLookup, options, cb) {
    if (entityGroups.length > 0) {
        Logger.trace({ entityGroups: entityGroups }, 'Looking up Entity Groups');

        let sessionToken = sessionManager.getSession(options.username, options.password);

        if (sessionToken) {
            // we are already authenticated.
            Logger.trace({ numSession: sessionManager.getNumSessions() }, 'Session Already Exists');

            _lookupWithSessionToken(entityGroups, entityLookup, options, sessionToken, function (err, results) {
                if (err && err === ERROR_EXPIRED_SESSION) {
                    // the session was expired so we need to retry remove the session and try again
                    Logger.trace({ err: err }, "Clearing Session");
                    sessionManager.clearSession(options.username, options.password);
                    _doLookup(entityGroups, entityLookup, options, cb);
                } else if (err) {
                    Logger.error({ err: err }, 'Error doing lookup');
                    cb(err);
                } else {
                    Logger.trace({ results: results }, "Logging results in dolookup");
                    cb(null, results);
                }
            });
        } else {
            // we are not authenticated so we need to login and get a sessionToken
            Logger.trace('Session does not exist. Creating Session');
            _login(options, function (err, sessionToken) {
                Logger.trace({ sessionToken: sessionToken }, 'Created new session');
                if (err) {
                    Logger.error({ err: err }, 'Error logging in');
                    // Cover the case where an error is returned but the session was still created.
                    if (err === ERROR_EXPIRED_SESSION) {
                        cb({
                            detail: 'Session Expired While Trying to Login'
                        });
                    } else {
                        cb(err);
                    }
                    return;
                }

                sessionManager.setSession(options.username, options.password, sessionToken);
                _doLookup(entityGroups, entityLookup, options, cb);
            });
        }
    } else {
        cb(null, []);
    }
}


function _lookupWithSessionToken(entityGroups, entityLookup, options, sessionToken, cb) {
    let lookupResults = [];

    let tqUri = options.url + "/indicators/";

    async.map(entityGroups, function (entityGroup, next) {
        _lookupEntity(entityGroup, entityLookup, sessionToken, options, next);
    }, function (err, results) {
        if (err) {
            cb(err);
            return;
        }

        Logger.trace({ results: results }, "Results from async map lookupEntity");

        results.forEach(tqItem => {
            if (tqItem.data.length > 0) {
                lookupResults.push({
                    entity: tqItem._entityObject,
                    data: {
                        summary: ["Class: " + tqItem.data[0].class + " Status: " + tqItem.data[0].status.name],
                        details: {
                            allData: tqItem.data,
                            url: tqUri
                        }
                    }
                });
            } else {
                // cache miss here
                lookupResults.push({
                    entity: tqItem._entityObject,
                    data: null
                });
            }
        });

        Logger.trace({ lookupResults: lookupResults }, 'Lookup Results');

        cb(null, lookupResults);
    });
}

function _handleRequestError(err, response, body, options, cb) {
    if (err) {
        cb(_createJsonErrorPayload("Unable to connect to TQ server", null, '500', '2A', 'ThreatQ HTTP Request Failed', {
            err: err,
            response: response,
            body: body
        }));
        return;
    }

    // Sessions will expire after a set period of time which means we need to login again if we
    // receive this error.
    // 401 is returned if the session is expired.
    if (response.statusCode === 401) {
        Logger.trace({ err: err, body: body }, "Received HTTP Status 401");
        cb(ERROR_EXPIRED_SESSION);
        return;
    }

    if (response.statusCode !== 200 && response.statusCode !== 201) {
        cb(_createJsonErrorPayload(response.statusMessage, null, response.statusCode, '2A', 'STAXX HTTP Request Failed', {
            response: response,
            body: body
        }));
        return;
    }

    cb(null, body);
}


function _login(options, done) {
    Logger.error('options are ', { options: options });

    //do the lookup
    let requestOptions = {
        method: 'POST',
        uri: options.url + '/api/token',
        body: {
            email: options.username,
            password: options.password,
            grant_type: "password",
            client_id: options.client,
        },
        json: true
    };

    requestWithDefaults(requestOptions, function (err, response, body) {
        if (err) {
            // generic HTTP error
            done(_createJsonErrorPayload("Unable to connect to TQ server", null, '500', '2A', 'Login Request Failed', {
                err: err,
                //response: response,
                body: body
            }));
            return;
        }

        if (response.statusCode === 400) {
            // invalid username and password
            done(_createJsonErrorPayload("User credentials are not valid", null, response.statusCode,
                '2B', 'Login Request Failed', {
                    err: err,
                    //response: response,
                    body: body
                }));
            return;
        }

        if (response.statusCode !== 200) {
            done(_createJsonErrorPayload("User credentials are not valid", null, response.statusCode,
                '2C', 'Login Request Failed', {
                    err: err,
                    //response: response,
                    body: body
                }));
            return;
        }

        // success if body has an `access_token` in it
        if (typeof body === 'object' && typeof body.access_token === 'string') {
            done(null, body.access_token);
        } else {
            done(_createJsonErrorPayload("Could not find access token in login response", null, response.statusCode,
                '2D', 'Login Request Failed', {
                    err: err,
                    //response: response,
                    body: body
                }));
        }
    });
}

function _lookupEntity(entitiesArray, entityLookup, apiToken, options, done) {
    //do the lookup
    let requestOptions = {
        method: 'GET',
        uri: options.url + "/api/indicators/search",
        qs: {
            limit: 10,
            value: entitiesArray[0],
            with: "tags,score,sources"
        },
        headers: {
            Authorization: "Bearer " + apiToken
        },
        json: true
    };


    requestWithDefaults(requestOptions, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, body) {
            if (err) {
                if (err === ERROR_EXPIRED_SESSION) {
                    Logger.trace({ err: err }, 'Session Expired');
                } else {
                    Logger.error({ err: err }, 'Error Looking up Entity');
                }

                done(err);
                return;
            }

            body._entityObject = entityLookup[entitiesArray[0].toLowerCase()];

            Logger.trace({ body: body }, "_lookupEntity Results");

            done(null, body);
        });
    });
}

/**
 * Helper method that creates a fully formed JSON payload for a single error
 * @param msg
 * @param pointer
 * @param httpCode
 * @param code
 * @param title
 * @returns {{errors: *[]}}
 * @private
 */
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
    let error = {
        detail: msg,
        status: httpCode.toString(),
        title: title,
        code: 'TQ_' + code.toString()
    };

    if (pointer) {
        error.source = {
            pointer: pointer
        };
    }

    if (meta) {
        error.meta = meta;
    }

    return error;
}

function startup(logger) {
    Logger = logger;


    let defaults = {};

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        defaults.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        defaults.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        defaults.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        defaults.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        defaults.proxy = config.request.proxy;
    }


    if (typeof config.request.rejectUnauthorized === 'boolean') {
        defaults.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    sessionManager = new SessionManager(Logger);

    requestWithDefaults = request.defaults(defaults);
}


function validateOptions(userOptions, cb) {
    let errors = [];
    if (typeof userOptions.url.value !== 'string' ||
        (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)) {
        errors.push({
            key: 'url',
            message: 'You must provide your TQ server URL'
        })
    }

    if (typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)) {
        errors.push({
            key: 'username',
            message: 'You must provide your TQ username'
        })
    }

    if (typeof userOptions.password.value !== 'string' ||
        (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)) {
        errors.push({
            key: 'password',
            message: 'You must provide your TQ username\'s password'
        })
    }

    if (typeof userOptions.client.value !== 'string' ||
        (typeof userOptions.client.value === 'string' && userOptions.client.value.length === 0)) {
        errors.push({
            key: 'username',
            message: 'You must provide your TQ username'
        })
    }
    cb(null, errors);
}

function onMessage(payload, integrationOptions, callback) {
    Logger.trace('on message called with', payload);

    let id = payload.data.id;
    let comment = payload.data.comment;

    let sessionToken = sessionManager.getSession(integrationOptions.username, integrationOptions.password);

    if (sessionToken) {
        _postComment(sessionToken, id, comment, integrationOptions, callback);
    } else {
        _login(integrationOptions, (err, sessionToken) => {
            Logger.trace({ sessionToken: sessionToken }, 'Created new session');
            if (err) {
                Logger.error({ err: err }, 'Error logging in');
                // Cover the case where an error is returned but the session was still created.
                if (err === ERROR_EXPIRED_SESSION) {
                    callback({
                        detail: 'Session Expired While Trying to Login'
                    });
                } else {
                    callback(err);
                }
                return;
            }

            sessionManager.setSession(options.username, options.password, sessionToken);
            _postComment(sessionToken, id, comment, integrationOptions, callback);
        });
    }
}

function _postComment(apiToken, id, comment, integrationOptions, callback) {
    let requestOptions = {
        method: 'POST',
        uri: `${integrationOptions.url}/api/indicators/${id}/comments`,
        body: {
            value: comment
        },
        headers: {
            Authorization: "Bearer " + apiToken
        },
        json: true
    };

    Logger.trace('sending comment to threatQ', requestOptions);

    requestWithDefaults(requestOptions, (err, resp, body) => {
        _handleRequestError(err, resp, body, integrationOptions, (err, body) => {
            if (err) {
                callback(err);
                return;
            }

            callback(null, { data: `sent comment ${comment}` });
        });
    });
}

module.exports = {
    doLookup: createEntityGroups,
    onMessage: onMessage,
    startup: startup,
    validateOptions: validateOptions
};