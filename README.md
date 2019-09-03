# Intrexx OAuth2/OpenID Connect Login Module

## Introduction

With the Intrexx OpenID Connect Login Module, Intrexx users can be authenticated via an external identity provider and Intrexx can be integrated into single sign-on environments. Intrexx uses the standardized OAuth2 or OpenID Connect procedure for this. The following external providers come into consideration:

- Microsoft Azure Active Directory
- MS Active Directory Federation Services v4.0
- Okta
- Keycloak
- Google
- GitHub
- or other identity providers that conform to OAuth2/OIDC

## Requirements

- Intrexx 18.03 with OU4 or higher or Intrexx 18.09
- The URL Rewrite Module is required for Intrexx 18.03 and Microsoft IIS to redirect the OAuth2 callbacks to the portal server

## Configuration

### Define login module

Before the module can be activated, it needs to be registered in the file "internal/cfg/LucyAuth.cfg". Insert the following block into
the file or include the line "IntrexxOAuth2LoginModule" in your existing login configuration:

Example: OpenID Connect and Intrexx standard authentication:

```text
IntrexxOAuth2
{
        de.uplanet.lucy.server.auth.module.intrexx.IntrexxOAuth2LoginModule sufficient
                debug=false;

        de.uplanet.lucy.server.auth.module.intrexx.IntrexxLoginModule sufficient
                de.uplanet.auth.allowEmptyPassword=true
                debug=true;

        de.uplanet.lucy.server.auth.module.anonymous.AnonymousLoginModule sufficient
                debug=true;
};
```

### Activate the login module using the example Microsoft Azure AD

The module is activated in the file "internal/cfg/om.cfg". Modify the entry for `binding scope="web"` to the login configuration from the LucyAuth.cfg with the OAuth2 Login Module. Insert a new `<oauth2>` section beneath `</authentication>`.

For example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <authentication anonymous="05CE8CE3035924F7D3088895F1D87DADD65CFAE4">
      <binding scope="web" auth-type="IntrexxOAuth2"/>
      <binding scope="client" auth-type="IntrexxAuth"/>
      <binding scope="webservice" auth-type="IntrexxAuth"/>
      <binding scope="odataservice" auth-type="ODataAuth"/>
      <binding scope="documentintegration" auth-type="IntrexxAuth"/>
      <webserver-configuration plain-text-auth="false" integrated-auth="false"/>
      <mobile-devices plain-text-auth="never"/>
   </authentication>

   <oauth2 name="azuread">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="id_token"
                auth-requires-nonce="true"
                auth-access-token-url="https://login.microsoftonline.com/common/oauth2/v2.0/token"
                auth-user-auth-url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                auth-pub-keys-src="https://login.microsoftonline.com/common/discovery/v2.0/keys"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://intrexx/portal/oauth2login"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
        <additional-redirect-params>
                <redirect-param key="response_type" value="id_token"/>
                <redirect-param key="response_mode" value="form_post"/>
        </additional-redirect-params>
   </oauth2>

   <security/>
   <organization default-container-guid="4B87C2470868AAB57BFB31958D1F73583FB3778E" default-distlist-guid="4B87C2470868AAB57BFB31958D1F73583FB3778E"/>
</configuration>
```

Here, replace `CLIENT_ID` and `CLIENT_SECRET` with the Client ID and Client Secret that you received when you registered Intrexx as an app in AzureAD. Furthermore, the redirect URL needs to be adjusted to your portal. Afterwards, the portal server needs to be restarted.

### Configure redirect rules for OAuth2 callbacks

When an anonymous user accesses the portal, the module automatically redirects them to the login page of the identity provider. Once they have logged in, they are then redirected to Intrexx with the ID token. So that this redirect back to Intrexx is performed correctly, you require a redirect rule for Intrexx in the front end web server.

#### Microsoft Internet Information Server

Install the IIS module "Url Rewrite" from Microsoft.
Afterwards, create a new redirect URL as described here:

<http://up-download.de/up/docs/intrexx-onlinehelp/8100/en/index.html?p=helpfiles/help.2.connectoren-office-365.html#IIS-configuration>

In the "Pattern" field enter the expression `oauth2login`. Enter the expression `default.asp?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet` in the "Rewrite URL" field.

#### Tomcat

If you are using Tomcat as the web server, the redirect for OAuth2 must be entered in the "server.xml" file in the installation directory /tomcat/conf. In the Host section, search for the following entry at the end of the file: 


```xml
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs" pattern="%h %l %u %t "%r" %s %b %D "%{User-Agent}i"" prefix="localhost_access_log" suffix=".txt"/>
```

Add the following entry underneath 

```xml
<Valve className="org.apache.catalina.valves.rewrite.RewriteValve" />
```

Afterwards, create a text file called "rewrite.config" with a text editor of your choice. Enter the following there:  

```xml
RewriteRule /<portalname>/oauth2login?(.*) /<portalname>/default.ixsp?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet&%{QUERY_STRING} [NC,L]
```

Please note that the portal name is case-sensitive. You can identify the portal name in the "Context" field in the portal properties. Move the rewrite.config file to the installation directory /tomcat/conf/Catalina/<host>. Afterwards, restart the Intrexx Tomcat Servlet Containers.

#### Intrexx 18.09 or later with Tomcat / IIS

A redirect rule is not required in this setting. The OAuth login end point is:

`/login/oic/authenticate`

### Import SSL certificates

If you are using the internal Intrexx certificate store, all of the SSL certificates used by the identity provider need to be imported there (Portal properties -> Certificates -> Download from URL). Alternatively, you can use the Intrexx Java Runtime certificate store (remove the JVM parameter `-Djavax.net.ssl.trustStore=internal/cfg/cacerts` in `internal/cfg/portal.wcf`).

### OAuth2 login button on the portal homepage

So that the authentication process for logging in via an external identity provider can be initiated from Intrexx, a request needs to be made to an Intrexx servlet that is informed by a query string parameter as to which provider should be used for the login (multiple providers can be defined in the om.cfg). The simplest way to do this is to add a login button to the portal login page (or another portal page). Open the file `\org\portal\internal\system\vm\html\login\logincore.vm` and insert the following line beneath the login form:

```html
<input class="Button_Standard" type="Button" onclick="location.href='?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet&oauthProvider=azuread';" value="Login with Azure AD">
```

Here, modify the `oauthProvider` parameter and enter the name of the provider definition from `om.cfg` as the value.

You can create multiple login buttons of this type for different providers.

### User login

Once a user clicks on one of the OAuth2 login buttons on the homepage, they will automatically be redirected to the provider and then back to Intrexx. Intrexx then receives the user information from the ID token and maps the token value to a field in the Intrexx user data to identify and log in a single Intrexx user. The mapping between the provider field and the Intrexx user field can be adjusted in om.cfg. Typically, the user's email address is used. It is important that the values in the selected user data field are unique. If multiple users are identified based on the token, the login is cancelled with an error.

### User replication

It is recommended to import/replicate the user data from an external identity provider. If you are using Azure AD or ADFS, this can be achieved via LDAP.

### Links with more information

<https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc>

<https://developers.google.com/identity/protocols/OpenIDConnect>

<https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-openid-connect-code>

<https://developer.okta.com/docs/api/resources/oidc>

### More configuration examples

```xml
<oauth2 name="azurev1">
        <provider
                auth-access-token-url="https://login.microsoftonline.com/common/oauth2/token"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-grant-type="authorization_code" auth-protocol="id_token"
                auth-provider-login-hint="This is a hint"
                auth-provider-prompt="none"
                auth-pub-keys-src="https://login.microsoftonline.com/common/discovery/keys"
                auth-redirect-url="https://localhost/test/oauth2login"
                auth-requires-nonce="true"
                auth-scheme="header"
                auth-scope="openid email"
                auth-user-auth-url="https://login.microsoftonline.com/common/oauth2/authorize"
                auth-user-info-url=""/>
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="upn"/>
        <additional-redirect-params>
                <redirect-param key="response_type" value="id_token"/>
                <redirect-param key="response_mode" value="form_post"/>
        </additional-redirect-params>
</oauth2>
<oauth2 name="azurev2">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="id_token"
                auth-requires-nonce="true"
                auth-access-token-url="https://login.microsoftonline.com/common/oauth2/v2.0/token"
                auth-user-auth-url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                auth-pub-keys-src="https://login.microsoftonline.com/common/discovery/v2.0/keys"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://localhost/test/oauth2login"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
        <additional-redirect-params>
                <redirect-param key="response_type" value="id_token"/>
                <redirect-param key="response_mode" value="form_post"/>
        </additional-redirect-params>
</oauth2>
<oauth2 name="google">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="code"
                auth-requires-nonce="false"
                auth-access-token-url="https://www.googleapis.com/oauth2/v4/token"
                auth-user-auth-url="https://accounts.google.com/o/oauth2/v2/auth"
                auth-pub-keys-src="https://www.googleapis.com/oauth2/v3/certs"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://localhost/test/oauth2login"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
</oauth2>
<oauth2 name="okta">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="code"
                auth-requires-nonce="true"
                auth-access-token-url="https://dev-xxxxx.oktapreview.com/oauth2/default/v1/token"
                auth-user-auth-url="https://dev-xxxxx.oktapreview.com/oauth2/default/v1/authorize"
                auth-pub-keys-src="https://dev-748399.oktapreview.com/oauth2/default/v1/keys"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://localhost/default.ixsp?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
</oauth2>
```

### Configuration reference

- GENERAL

`unique_identifier : string [any string but unique among the oauth2 providers]`

- MAPPING

```text
auth_DB_field_name_for_claim :  string [the name of the field respectively the column in the db used to validate the claim]
auth_provider_field_for_claim  :  string [the name of the field in the id token (json) used as claim]
```

- OAUTH2/OIDC

```text
 auth_grant_type: 'authorization_code' [the grant type, can generally be 'authorization_code', 'implicit', ...  ] here only authorization_code
 auth_scheme: 'header'
 auth_protocol  :  string [code | id_token]
 auth_requires_nonce  :  boolean [if the provider requires a nonce]
 auth_access_token_url :  string [the providers url for the token]
 auth_user_auth_url  :  string [the providers url for the authorization]
 auth_user_info_url  :  string [the providers url for the user info endpoint]
 auth_pub_keys_src  :  string [the src of the public keys of the provider. a url in terms of AWS, AZURE, etc]
 auth_oauth2_scope :  string [the scope containing at least 'openid' and the identifier of the required claim]
 auth_oauth2_client_id :  string [the client id given by the provider]
 auth_oauth2_client_secret :  string [the client secret given by the provider]
 auth_oauth2_redirect_url   :  string [the url configured at the provider as redirect]
 auth_provider_prompt   :  string [whether to show a prompt at all 'none' and 'consent' ar common among azure and google]
 auth_provider_login_hint  :  string [hint to show with the login prompt]
```

- ADDITIONAL additional params as elements

```text
 response_type : id_token
 response_mode : form_post
 ```