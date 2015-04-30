package io.vertx.ext.httpservicefactory;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public enum ValidationPolicy {

  /**
   * Never do any check.
   */
  NEVER,

  /**
   * Validate the deployment when a signature exists for this deployment: when the signature cannot be verified
   * the deployment fails.
   */
  VERIFY,

  /**
   * Any deployment must be verified to be deployed.
   */
  ALWAYS,

}
