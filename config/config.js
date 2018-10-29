module.exports = {
    /**
     * Name of the integration which is displayed in the Polarity integrations user interface
     *
     * @type String
     * @required
     */
    name: "ThreatQ",
    /**
     * The acronym that appears in the notification window when information from this integration
     * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
     * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
     * here will be carried forward into the notification window.
     *
     * @type String
     * @required
     */
    acronym: "TQ",
    /**
     * Description for this integration which is displayed in the Polarity integrations user interface
     *
     * @type String
     * @optional
     */
    description: "Threat Quotient integration for IP's, hashes and domains",
    entityTypes: ['IPv4', 'IPv6', 'hash', 'domain'],
    customTypes: [
        {
            "key": 'cidr',
            "regex": /((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[1-2]?[0-9])/
        },
    ],
    /**
     * An array of style files (css or less) that will be included for your integration. Any styles specified in
     * the below files can be used in your custom template.
     *
     * @type Array
     * @optional
     */
    "styles": [
        "./styles/tq.less"
    ],
    /**
     * Provide custom component logic and template for rendering the integration details block.  If you do not
     * provide a custom template and/or component then the integration will display data as a table of key value
     * pairs.
     *
     * @type Object
     * @optional
     */
    block: {
        component: {
            file: "./component/tq.js"
        },
        template: {
            file: "./templates/tq.hbs"
        }
    },
    request: {
        // Provide the path to your certFile. Leave an empty string to ignore this option.
        // Relative paths are relative to the STAXX integration's root directory
        cert: '',
        // Provide the path to your private key. Leave an empty string to ignore this option.
        // Relative paths are relative to the STAXX integration's root directory
        key: '',
        // Provide the key passphrase if required.  Leave an empty string to ignore this option.
        // Relative paths are relative to the STAXX integration's root directory
        passphrase: '',
        // Provide the Certificate Authority. Leave an empty string to ignore this option.
        // Relative paths are relative to the STAXX integration's root directory
        ca: '',
        // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
        // the url parameter (by embedding the auth info in the uri)
        proxy: '',
        /**
         * If set to false, the integeration will ignore SSL errors.  This will allow the integration to connect
         * to STAXX servers without valid SSL certificates.  Please note that we do NOT recommending setting this
         * to false in a production environment.
         */
        rejectUnauthorized: false
    },
    logging: {
        // directory is relative to the this integrations directory
        // e.g., if the integration is in /app/polarity-server/integrations/virustotal
        // and you set directoryPath to be `integration-logs` then your logs will go to
        // `/app/polarity-server/integrations/integration-logs`
        // You can also set an absolute path.  If you set an absolute path you must ensure that
        // the directory you specify is writable by the `polarityd:polarityd` user and group.

        //directoryPath: '/var/log/polarity-integrations',
        level: 'trace',  //trace, debug, info, warn, error, fatal
    },
    /**
     * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
     * as an array of option objects.
     *
     * @type Array
     * @optional
     */
    options: [
        {
            key: "url",
            name: "ThreatQ Server URL",
            description: "The URL for your ThreatQ server which should include the schema (i.e., http, https) and port if required",
            default: "",
            type: "text",
            userCanEdit: false,
            adminOnly: true
        },
        {
            key: "username",
            name: "Username",
            description: "Your TQ username you want the integration to authenticate as (typically an email address)",
            default: "",
            type: "text",
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: "password",
            name: "Password",
            description: "The password for the provided username you want the integration to authenticate as",
            default: '',
            type: "password",
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: "client",
            name: "Client ID",
            description: "The Client ID for your ThreatQ deployment.  (accessible at https://<yourserver>/assets/js/config.js)",
            default: '',
            type: "text",
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: "ignorePrivateIps",
            name: "Ignore Private IPs",
            description: "If set to true, private IPs (RFC 1918 addresses) will not be looked up (includes 127.0.0.1, 0.0.0.0, and 255.255.255.255)",
            default: true,
            type: "boolean",
            userCanEdit: false,
            adminOnly: true
        }
    ]
};