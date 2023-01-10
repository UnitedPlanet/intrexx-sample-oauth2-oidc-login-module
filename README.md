# Intrexx OAuth2/OpenID Connect Login Module

## Introduction

With the Intrexx OpenID Connect Login Module, Intrexx users can be authenticated via an external identity provider and Intrexx can be integrated into single sign-on environments. Intrexx uses the standardized OAuth2 or OpenID Connect procedure for this. The following external providers come into consideration:

- Microsoft Azure Active Directory
- MS Active Directory Federation Services v4.0
- Okta
- Keycloak
- Google
- GitHub
- or other identity providers that conform to OAuth2/OpenID Connect

## Requirements

- Intrexx 19.03 or higher. For 18.03 checkout the `v18.03` branch.

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
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
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

### Import SSL certificates

If you are using the internal Intrexx certificate store, all of the SSL certificates used by the identity provider need to be imported there (Portal properties -> Certificates -> Download from URL). Alternatively, you can use the Intrexx Java Runtime certificate store (remove the JVM parameter `-Djavax.net.ssl.trustStore=internal/cfg/cacerts` in `internal/cfg/portal.wcf`).

### OAuth2 login button on the portal homepage

So that the authentication process for logging in via an external identity provider can be initiated from Intrexx, a request needs to be made to an Intrexx servlet that is informed by a query string parameter as to which provider should be used for the login (multiple providers can be defined in the om.cfg). For testing purposes, the simplest way to do this is to add a login button to an Intrexx portal page:

```html
<input class="Button_Standard" type="Button" onclick="location.href='?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet&oauthProvider=azuread';" value="Login with Azure AD">
```

Here, modify the `oauthProvider` parameter and enter the name of the provider definition from `om.cfg` as the value.

You can create multiple login buttons of this type for different providers.

For production systems it is highly recommended to create a custom portlet for the login button and place this on the portal start page. This repository contains an example Intrexx app with a login portlet (GoogleAuthPortlet.lax).

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
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
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
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
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
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
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
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
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
db-field-name:  string [the property name or GUID of the Intrexx user schema field used to validate the claim]
provider-claim-fieldname  :  string [the name of the field in the id token (json) used as claim]

Examples:

<mapping db-field-name="GUID-of-db-field" provider-claim-fieldname="email" enable-user-registration="false"/>
<mapping db-field-name="loginLwr" provider-claim-fieldname="preferred_username" enable-user-registration="false"/>
<mapping db-field-name="emailBiz" provider-claim-fieldname="email" enable-user-registration="false"/>
```

- OAUTH2/OIDC

```text
 auth_grant_type: 'authorization_code' [the grant type, can generally be 'authorization_code', 'implicit', ...  ] here only authorization_code
 auth_scheme: 'header'
 auth_protocol:  string [code | id_token]
 auth_requires_nonce:  boolean [if the provider requires a nonce]
 auth_access_token_url:  string [the providers url for the token]
 auth_user_auth_url:  string [the providers url for the authorization]
 auth_user_info_url:  string [the providers url for the user info endpoint]
 auth_pub_keys_src:  string [the src of the public keys of the provider. a url in terms of AWS, AZURE, etc]
 auth_oauth2_scope:  string [the scope containing at least 'openid' and the identifier of the required claim]
 auth_oauth2_client_id:  string [the client id given by the provider]
 auth_oauth2_client_secret:  string [the client secret given by the provider]
 auth_oauth2_redirect_url:  string [the url configured at the provider as redirect]
 auth_provider_prompt:  string [whether to show a prompt at all 'none' and 'consent' ar common among azure and google]
 auth_provider_login_hint:  string [hint to show with the login prompt]
```

- ADDITIONAL additional params as elements

```text
 response_type: id_token
 response_mode: form_post
 ```

### User Registration

When the mapping attribbute `enable-user-registration` is set to true, user accounts will be created automatically when user authentication was successful but a corresponding Intrexx user account does not exist. In this case, a custom Groovy script will be executed which leverages the Groovy user management API to create a new user. If a user could be created successfully, they will be logged in automatically. If an user account already exists but is disabled, the user will not be logged in before an Intrexx administrator enables the account again. If an account was deleted before, it will be re-created. The user details can be accessed via the script variable accessTokenDetails (of type HashMap). The map contains also the actual OAuth2 access token which can be used to send further HTTP requests to the external API.

Edit `internal/cfg/om.cfg`:

```xml
 <mapping db-field-name="emailBiz" provider-claim-fieldname="email" enable-user-registration="true"/>
```

Copy `internal/cfg/spring/00-oauth2-context.xml` to `internal/cfg/spring/custom/00-oauth2-context.xml` and add the following section to the `defaultOAuth2Login` bean definition:

```xml
    <!-- The OAuth2 login bean-->
    <bean id="defaultOAuth2Login" class="de.uplanet.lucy.server.login.OAuth2LoginBean">
        ...
        <!-- set to false only when in development mode, otherwise changes to the script requires portal server restart -->
        <property name="cacheCompiledScript" value="true" />
        <!-- internal path to the Groovy user registration script -->
        <property name="userMappingScript" value="internal/cfg/oauth2_user_registration.groovy" />
        <property name="userUpdateScript" value="internal/cfg/oauth2_user_update.groovy"/>
        ...
    </bean>
```

Add a new file `internal/cfg/oauth2_user_registration.groovy`:

```groovy
// creates new user after successful authentication

g_syslog.info(accessTokenDetails)

// Intrexx internal class ID for tenant containers
TENANT_CLASS_ID = 12

try
{
	//check if tenant (CompanyID) exists
	def tenant = g_om.getOrgStructure().findContainerNode(accessTokenDetails["CompanyID"])

	if (tenant) {
		assert tenant.classId == TENANT_CLASS_ID
	}
	else
	{
		// create the tenant
		tenant = g_om.createContainer("TENANT", {
			container = "Tenants"  // the parent container for new tenants
			name = accessTokenDetails["CompanyID"]
			description = accessTokenDetails["Company"]
			//set("CompanyID", accessTokenDetails["CompanyID"]) add custom schema attributes
		})
	}

	// prepare the user groups from roles
	def roles = accessTokenDetails["Roles"]
	def ixRoles = [:]

	if (roles) {
		roles.forEach { roleValues ->
			ixGroup = ""

			// map the roles to Intrexx user groups (by name or GUID)
			switch(roleValues["RoleType"]) {
				case "SYSADMIN": ixGroup = "Administratoren"; break;
				case "ADMIN": ixGroup = "Administratoren"; break;
				case "USERS": ixGroup = "Benutzer"; break;
				default: ixGroup = "Benutzer"
			}

			ixRoles[ixGroup] = 1
		}
	}

	// generate a random password
	def pwGuid = newGuid()
	def pw = g_om.getEncryptedPassword(["password": pwGuid])

	// create the new user
	def user = g_om.createUser {
		container     = "System" // name of the parent container for new users
		name          =  accessTokenDetails["user"]
		password      =  pw
		loginName     =  accessTokenDetails["user"]
		emailBiz      =  accessTokenDetails["email"]
		description   = "OIDC user created at ${now().withoutFractionalSeconds}"
		TENANT        =  tenant.guid

		// a list of GUIDs or names of user groups
		//memberOf = ["6AA80844C3C99EF93BF4536EB18605BF86FDD3C5"]
		memberOf = ixRoles.keySet()
	}

	g_syslog.info("Created user from OIDC: ${user.loginName}/${tenant.name}")
	g_syslog.info("User groups" + ixRoles.keySet())
	return true
}
catch (Exception e)
{
	g_syslog.error("Failed to create user: " + e.message, e)
	return false
}
```

## Existing User Update

When the `enable-user-registration` attribute in om.cfg ist set to `true`, a further custom Groovy script can be defined to update an existing user after successful login. The user details can be accessed via the script variable `accessTokenDetails` (of type `HashMap`) along with the current Intrexx user object `ixUserRecord`. The map contains also the actual OAuth2 access token which can be used to send further HTTP requests to an external API.

In `internal/cfg/spring/custom/00-oauth2-context.xml` add the following section to the `defaultOAuth2Login` bean definition:

```xml
    <!-- The OAuth2 login bean-->
    <bean id="defaultOAuth2Login" class="de.uplanet.lucy.server.login.OAuth2LoginBean">
        ...
        <!-- set to false only when in development mode, otherwise changes to the script requires portal server restart -->
        <property name="cacheCompiledScript" value="true" />
        <!-- internal path to the Groovy user registration script -->
        <property name="userMappingScript" value="internal/cfg/oauth2_user_registration.groovy" />
        <property name="userUpdateScript" value="internal/cfg/oauth2_user_update.groovy"/>
        ...
    </bean>
```

Add a new file `internal/cfg/oauth2_user_update.groovy`:

```groovy
// log user details
g_log.info(accessTokenDetails)
g_log.info(accessTokenDetails["ixUserRecord"])

// update user/roles etc. as in registration script

return true
```

## Troubleshooting

### Log output

To trace the authentication flow, you can enable detailed output in the Intrexx portal.log file. Open the file `internal/cfg/log4j2.xml` and add another section. Restart the portal server afterwards.

```xml
<!-- logging for OIDC auth -->
<Logger name="de.uplanet.lucy.server.composer.ixservlet.OAuth2LoginIxServlet" level="debug" additivity="false">
    <AppenderRef ref="DailyFile"/>
</Logger>
<Logger name="de.uplanet.lucy.server.login" level="debug" additivity="false">
    <AppenderRef ref="DailyFile"/>
</Logger>
```

Furthermore, you can add this section to trace the HTTP requests/responses between Intrexx and the IdP.

```xml
	<Logger name="org.apache.http" level="INFO"  additivity="false">
		<AppenderRef ref="Console"/>
		<!-- <AppenderRef ref="DailyFile"/>-->
	</Logger>
	<Logger name="org.apache.http.impl.conn" level="INFO"  additivity="false">
		<AppenderRef ref="Console"/>
		<!-- <AppenderRef ref="DailyFile"/>-->
	</Logger>
	<Logger name="org.apache.http.wire" level="INFO"  additivity="false">
		<AppenderRef ref="Console"/>
		<!-- <AppenderRef ref="DailyFile"/>-->
	</Logger>
```

Do not forget to remove these sections after analysing issues as they degrade runtime performance and pollute the server log file.
