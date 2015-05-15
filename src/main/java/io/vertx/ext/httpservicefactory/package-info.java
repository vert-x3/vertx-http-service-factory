/**
 * = Vert.x Http Service Factory
 *
 * The http service factory is a Vert.x service factory for deploying services from an http server.
 *
 * ----
 * vertx run https://myserver.net/myverticle.zip::my-service
 * ----
 *
 * Although it looks like an http URL, it is a verticle identifer with a factory bound to the _https_ prefix (_http_
 * also supported).
 *
 * The service identifier is made up of the suffix to form an _http_ URL or the archive that contains the service,
 * followed by a double colon `::` and a service name.
 *
 * The service name is used to find the service descriptor file inside the artifact which is named by the service name with
 * a `.json` extension. This is explained in the link:https://github.com/vert-x3/vertx-service-factory[Service Verticle Factory]
 * documentation.
 *
 * For example, to deploy a service that exists in an hosted at `https://myserver.net/myverticle.zip` called `my-service`
 * you would use the strng `https://myserver.net/myverticle.zip::my-service`.
 *
 * Given this string, the verticle factory will use the Vert.x http client try and download the resource
 * `https://myserver.net/myverticle.zip`.
 *
 * It then constructs a classpath including this archive and creates a classloader with that classpath in order
 * to load the service using the standard link:https://github.com/vert-x3/vertx-service-factory[Service Verticle Factory].
 *
 * The Service Verticle Factory will look for a descriptor file called `my-service.json on the constructed classpath to
 * actually load the service.
 *
 * Given a service identifier the service can be deployed programmatically e.g.:
 *
 * ----
 * vertx.deployVerticle("https://myserver.net/myverticle.zip::my-service", ...)
 * ----
 *
 * Or can be deployed on the command line with:
 *
 * ----
 * vertx run https://myserver.net/myverticle.zip::my-service
 * ----
 *
 * The service name can be omitted when the service jar `META-INF/MANIFEST` contains a `Main-Verticle`entry that
 * declares the verticle to run:
 *
 * ----
 * vertx.deployVerticle("https://myserver.net/myverticle.zip", ...)
 * ----
 *
 * And the manifest contains:
 *
 * ----
 * Main-Verticle: service:my.service
 * ----
 *
 * Of course it can be deployed on the command line with:
 *
 * ----
 * vertx run https://myserver.net/myverticle.zip
 * ----
 *
 * == Http client configuration
 *
 * Files are downloaded using Vert.x http client, by default the https client is configured with the `ssl=true`
 * and `trustAll=true`. The default client options can be overriden to use specific configurations with the
 * _vertx.httpServiceFactory.httpClientOptions_ system property and the _vertx.httpServiceFactory.httpsClientOptions_
 * system property, these properties are valid for any http resource.
 *
 * === Client authentication
 *
 * The client supports basic authentication via the _vertx.httpServiceFactory.authUsername_ and
 * _vertx.httpServiceFactory.authPassword_ system properties.
 *
 * Authentication is done only for services (i.e basic authentication will not be done for key servers) and only using
 * an https connection.
 *
 * === Proxy server configuration
 *
 * The http client can be configured to support a proxy server with the _vertx.httpServiceFactory.proxyHost_ and
 * _vertx.httpServiceFactory.proxyPort_ system properties.
 *
 * == Public key servers
 *
 * Signed artifacts signatures are verifed using a public key, public key are retrieved from a public key server.
 *
 * The public key server uri can be configured with the _vertx.httpServiceFactory.keyserverURITemplate_ system property.
 * The URI template is used to create the public key URI this way:
 *
 * ----
 * String.format(keyserverURITemplate, signature.getKeyID())
 * ----
 *
 * When the property is not set, the default public key server is the _SKS OpenPGP Public Key Server_ server used and
 * the uri template used is : `http://pool.sks-keyservers.net:11371/pks/lookup?op=get&options=mr&search=0x%016X`
 * this server will server public key resources with the _application/pgp-keys_ media type.
 *
 * The Json https://keybase.io/docs/api/1.0/call/key/fetch[format] sent by Keybase.io is also support. Keybase.io
 * can be used as a public key server with `https://keybase.io/_/api/1.0/key/fetch.json?pgp_key_ids=%016X` URI template.
 *
 * == Validation policy
 *
 * The validation policy governs how downloaded services are validated, the _vertx.httpServiceFactory.validationPolicy_
 * system property configures the behavior of the verticle factory when it attemps to deploy a downloaded service file:
 *
 * - _none_ : the service file is just deployed as is
 * - _verify_ : the service file is verified when there is a corresponding _.asc_ signature file, otherwise it is
 * not verified. If the signature cannot be verified, the deployment fails.
 * - _mandatory_: the service file must have a corresponding _.asc_ signature file and the signature must be verified.
 *
 * The default validation policy is *_verify_*.
 *
 * == Cache directory
 *
 * The cache directory stores the files used by the http service factory after download:
 *
 * - deployed services
 * - service signatures
 * - public keys
 *
 * The cached files are named after the percent encoded download URL:
 *
 * ----
 * -rw-r--r--  1 julien  staff   270 May  3 21:44 http%3A%2F%2Flocalhost%3A8080%2Fthe_verticle.zip
 * -rw-r--r--  1 julien  staff   473 May  3 21:44 http%3A%2F%2Flocalhost%3A8080%2Fthe_verticle.zip.asc
 * -rw-r--r--  1 julien  staff  1768 May  3 21:44 http%3A%2F%2Flocalhost%3A8081%2Fpks%2Flookup%3Fop%3Dget%26options%3Dmr%26search%3D0x9F9358A769793D09
 * ----
 *
 * The default cache directory _.vertx_ can be set to a specific location with the _vertx.httpServiceFactory.cacheDir_
 * system property.
 *
 */
@Document(fileName = "index.adoc")
package io.vertx.ext.httpservicefactory;

import io.vertx.docgen.Document;