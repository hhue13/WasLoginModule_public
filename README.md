# OidcLoginModule
JAAS login module to be used for transient users in a DX environment with OpenID Connect TAI authentication

The login module accepts the following custom properties:

- jwk.endpoint.url – this must match the provider_<x>.jwkEndpointUrl custom TAI property
- transientidp.basedn.suffix – this must match the -Dtransparent.suffix=<value> provided when the transparent user registry was created (see: 3.6 Enable transient users in DX)
- transientidp.buildgroupsfor – this must match the value of the buildgroupsfor custom property configured for the transparent user registry
- group.claim.name – this must match the provider_<1>.groupIdentifier custom TAI property
- group.dn.format.string – This must match the FQDN pattern of the groups being use for DX/WAS role assignment

# SamlLoginModule
JAAS login module to be used for transient users in a DX environment with OpenID Connect TAI authentication

The login module accepts the following custom properties:
- default.realm.name - Specifies the default realm name of the cell
- email.domain - The eMail domain being used as the eMail domain for the transient user. The user's eMail is <user-id>@<email.domain>
- transientidp.basedn.suffix - this must match the -Dtransparent.suffix=<value> provided when the transparent user registry was created via `<wp_profile_home>/ConfigEngine/ConfigEngine.sh enable-transient-user`
- transientidp.buildgroupsfor - this must match the value of the buildgroupsfor custom property configured for the transparent user registry
