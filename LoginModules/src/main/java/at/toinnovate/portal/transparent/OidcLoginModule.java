/********************************************************************
Copyright 2016  IBM Corp.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
********************************************************************/

/*******************************************************************
Copyright 2019  2innovate IT consulting
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

Based on the work documented at
https://developer.ibm.com/digexp/docs/docs/integration/google-openid-connect-with-ibm-digital-experience/
downloaded from: https://www.ibm.com/developerworks/community/files/app#/file/f02c4fda-6a26-41c4-9b0f-ffc35d472a10?comment=cd1f7dab-9c12-41f7-8c32-94bf7d4e96c9

File was adapted to meet specific project requirements
*******************************************************************/
package at.toinnovate.portal.transparent;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InitialContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

import com.ibm.json.java.JSONArray;
import com.ibm.json.java.JSONObject;
import com.ibm.portal.auth.tai.ExternalIdentityCredential;
import com.ibm.websphere.security.UserRegistry;
import com.ibm.wsspi.security.auth.callback.WSTokenHolderCallback;
import com.ibm.wsspi.security.token.AttributeNameConstants;

public class OidcLoginModule implements LoginModule {

	private static final String LOGGER_CLASS = OidcLoginModule.class.getName();
	private static final Logger LOGGER = Logger.getLogger(LOGGER_CLASS);
	private static final Level LOG_LEVEL = Level.FINE;
	private static final String NAME_JWK_ENDPOINT_URL = "jwk.endpoint.url";
	// transientidp.basedn.suffix must match the base entry of the transientidp repository in the VMM
	private static final String TRANSIENT_IDP_SUFFIX_DEFAULT = "o=transparent";
	private static final String TRANSIENT_IDP_SUFFIX_KEY = "transientidp.basedn.suffix";
	// transientidp.vp.suffix must match buildgroupsfor value! For example o=base
	private static final String TRANSIENT_PROVIDER_SUFFIX_DEFAULT = "base";
	private static final String TRANSIENT_PROVIDER_SUFFIX_KEY = "transientidp.buildgroupsfor";
	// name of the group claim in the JWT. A  JSONArray of strings with the group names
	private static final String GROUP_CLAIM_NAME_DEFAULT = "groupIds";
	private static final String GROUP_CLAIM_NAME_KEY = "group.claim.name";
	private static final String GROUP_DN_FORMAT_STRING_DEFAULT = "{0}";
	private static final String GROUP_DN_FORMAT_STRING_KEY = "group.dn.format.string";
	private static HttpsJwks httpsJkws = null;
	private static String idpSuffix = null;
	private static String providerSuffix = null;
	private static String groupClaimName = null;
	private static String groupDnFormatString = null;
	private Subject currentSubject;
	private CallbackHandler currentCallbackHandler;
	private Map<String, Object> currentSharedState;
	private Map<String, Object> currentOptions;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		final String METHOD_NAME = "initialize";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if (IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		currentSubject = subject;
		currentCallbackHandler = callbackHandler;
		currentSharedState = (Map<String, Object>) sharedState;
		currentOptions = (Map<String, Object>) options;

		// initialize the static variables for the idp and provider suffix
		if (idpSuffix == null) {
			setIdpSuffix();
			if (IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("idpSuffix set to: '%s'", idpSuffix));
		}
		if (providerSuffix == null) {
			setProviderSuffix();
			if (IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("providerSuffix set to: '%s'", providerSuffix));
		}
		if (groupClaimName == null) {
			setGroupClaimName();
			if (IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("groupClaimName set to: '%s'", groupClaimName));
		}

		if (groupDnFormatString == null) {
			setGroupDnFormatString();
			if (IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("groupDnFormatString set to: '%s'", groupDnFormatString));
		}

		if (IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME);
	}

	@Override
	public boolean login() throws LoginException {
		final String METHOD_NAME = "login()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if (IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);
		Hashtable<?,?> privateCredentials = getHashtableFromSubject(currentSubject);
		String jwtToken = null;
		if(privateCredentials != null){
			jwtToken = (String) privateCredentials.get("id_token");
		}
		String uniqueid = "";
		boolean success = false;
		Hashtable<String, Object> hashtable;
		Callback callbacks[] = new Callback[3];
		callbacks[0] = new javax.security.auth.callback.NameCallback("Username:");
		callbacks[1] = new javax.security.auth.callback.PasswordCallback("Password:", false);
		callbacks[2] = new com.ibm.wsspi.security.auth.callback.WSTokenHolderCallback("Authz Token List:");

		try {
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "Calling currentCallbackHandler");

			currentCallbackHandler.handle(callbacks);
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "currentCallbackHandler finished ..");

			boolean requiresLogin = ((WSTokenHolderCallback) callbacks[2]).getRequiresLogin();
			if(IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "requires login? : {0}",
						new Object[]{requiresLogin});
			// check if login at all is required correct position in queue)
			if (requiresLogin) {

				String username = ((NameCallback) callbacks[0]).getName();
				if (username != null) {
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "username is " + username);
					try {
						// try to find valid user for given username/eMail
						InitialContext ctx = new InitialContext();
						UserRegistry reg = (UserRegistry) ctx.lookup("UserRegistry");
						uniqueid = reg.getUniqueUserId(username);
					} catch (com.ibm.websphere.security.EntryNotFoundException e1) {
						// entry was not found - or not unique in defaultRealm
						// create realmScoped DN to support transient AC-groups
						// Global security > Federated repositories >
						// transientidp : buildgroupsfor
						if (IS_LOGGABLE)
							LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME,
									"Login Module - transient for base realm");

						uniqueid = String.format("uid=%s,%s,%s", username, providerSuffix, idpSuffix);
						Object o = currentSharedState.get(AttributeNameConstants.WSCREDENTIAL_PROPERTIES_KEY);
						if(o != null && o instanceof Hashtable<?, ?>){
							if (IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "hashtable casted from WSCREDENTIAL_PROPERTIES_KEY");
							hashtable = (Hashtable<String, Object>) o;
						}else {
							if (IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "created new hashtable");
							hashtable = new Hashtable<String, Object>();
						}

						if(jwtToken != null){
							final JSONObject userInfoResponse = getUserDataFromJwtToken(jwtToken);
							hashtable = mapUserAttributesToHashtable(userInfoResponse, hashtable);
						}
						if (IS_LOGGABLE)
							LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "adding uniqueid to WSCREDENTIAL_UNIQUEID+WSCREDENTIAL_SECURITYNAME ");
						hashtable.put(AttributeNameConstants.WSCREDENTIAL_UNIQUEID, uniqueid);
						hashtable.put(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME, uniqueid);
						if (IS_LOGGABLE)
							LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "added uniqueid to WSCREDENTIAL_UNIQUEID+WSCREDENTIAL_SECURITYNAME ");

						currentSubject.getPublicCredentials().add(hashtable);
						currentSubject.getPublicCredentials().add(
								new ExternalIdentityCredential(hashtable));
						if (IS_LOGGABLE)
							LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "added external identity credentials");

						currentSharedState.put(AttributeNameConstants.WSCREDENTIAL_PROPERTIES_KEY, hashtable);
						success = true;
						if (IS_LOGGABLE)
							LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "set success to true");
					} catch (Exception e2) {
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, e2.getMessage(), e2.getCause());
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "Login Module failed for user lookup");
					}
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "uniqueid = " + uniqueid);
				} else {
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "user name is null");
				}
			} else {
				success = true;
				if (IS_LOGGABLE)
					LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "This is a repeate login, nothing to do.");
			}
		} catch (Exception e) {
			LOGGER.logp(Level.WARNING, LOGGER_CLASS, METHOD_NAME, e.getMessage(), e.getCause());
			throw new LoginException(e.getMessage());
		}


		if (success) {
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "success with uniqueid = " + uniqueid);

		} else {
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "failed with uniqueid = " + uniqueid);
		}

		if (IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, success);
		return success;

	}

	@Override
	public boolean commit() throws LoginException {
		return false;
	}

	@Override
	public boolean abort() throws LoginException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean logout() throws LoginException {
		currentSubject.getPublicCredentials().clear();
		currentSharedState.remove(AttributeNameConstants.WSCREDENTIAL_PROPERTIES_KEY);
		return true;
	}


	/**
	 * Extracts the private credentials from the subject
	 * @param subject
	 * @return returns null if no Hashtable is found in the private credentials of the subject otherwise
	 * the found Hashtable is returned
	 */
	private Hashtable<?,?> getHashtableFromSubject(Subject subject){
		final String METHOD_NAME = "getHashtableFromSubject(Subject)";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME, subject);
		Hashtable<?,?> table = null;
		Set<Object> cred = subject.getPrivateCredentials();
		if(IS_LOGGABLE)
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "size of private credential set is {0},",
					new Object[] {cred.size()});
		Iterator<Object> iterator = cred.iterator();
		while(iterator.hasNext()){
			Object o =iterator.next();
			if(o instanceof Hashtable){
				table = (Hashtable<?,?>) o;
				break;
			}

		}
		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, table);
		return table;
	}

	/**
	 * This method extracts user information from the JSONObject and adds it according
	 * to the portal user management architecture to the provided hashtable
	 * @param userInfo JSONObject with user info according to OpenID Connect specification
	 * @param hashtable the user information is added to this table
	 * @return A hashtable where the user information is mapped according to the portal user management architecture
	 */
	private Hashtable<String, Object> mapUserAttributesToHashtable(JSONObject userInfo, Hashtable<String, Object> hashtable){
		final String METHOD_NAME = "mapUserAttributesToHashtable(JSONObject, Hashtable)";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);
		String givenName = null;
		String familyName = null;
		String email = null;
		String name = null;
		String id = null;
		String picture = null;
		JSONArray jsonGroupArray = null;

		id = (String) userInfo.get("sub");
		givenName = (String) userInfo.get("given_name");
		familyName = (String) userInfo.get("family_name");
		name = (String) userInfo.get("name");
		email = (String) userInfo.get("email");
		picture = (String) userInfo.get("picture");
		jsonGroupArray = (JSONArray) userInfo.get(groupClaimName);
		if(IS_LOGGABLE)
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME,
					"id: {0}, given name: {1}, family name: {2}, name: {3}, email: {4}, groups: {5}",
					new Object[]{id, givenName, familyName, name, email, jsonGroupArray.toString()});

		// add user attributes to be table to show them in portal
		if (familyName != null) {
			hashtable.put("sn", familyName);
			if(IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("added %s with value '%s' to table", "sn", familyName));
		} else {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "sn not added to table as it is null");
		}
		if (name != null) {
			hashtable.put("cn", name);
			if(IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("added %s with value '%s' to table", "cn", name));
		} else {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "cn not added to table as it is null");
		}

		if (id != null) {
			hashtable.put("uid", id);
			if(IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("added %s with value '%s' to table", "uid", id));
		} else {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "uid not added to table as it is null");
		}

		if (givenName != null) {
			hashtable.put("givenName", givenName);
			hashtable.put("displayName", givenName);
			if(IS_LOGGABLE) {
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("added %s with value '%s' to table", "givenName", givenName));
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("added %s with value '%s' to table", "displayName", givenName));
			}
		} else {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "givenName not added to table as it is null");
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "displayName not added to table as it is null");
		}

		if (email != null) {
			hashtable.put("ibm-primaryEmail", email);
			if(IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("added %s with value '%s' to table", "ibm-primaryEmail", email));
		} else {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "ibm-primaryEmail not added to table as it is null");
		}

		if (picture != null) {
			hashtable.put("jpegPhoto", picture);
			if(IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "added jpegPhoto to table");
		} else {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "jpegPhoto not added to table as it is null");
		}


		if (jsonGroupArray != null) {
			// hashtable.put("jpegPhoto", picture);
			if(IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("processing groupsString '%s' to hashtable", new Object[]{jsonGroupArray.toString()}));

			ArrayList<String> groupsArray = convertJSONArrayToStringArrayList(jsonGroupArray);

			if(IS_LOGGABLE) {
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "added the following groups to hashtable:");
				for (String groupInArrayList : groupsArray) {
					LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("- '%s'", groupInArrayList));
				}
			}
			hashtable.put( AttributeNameConstants.WSCREDENTIAL_GROUPS, groupsArray );
		} else {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "groupsString not added to table as it is null");
		}


		if(IS_LOGGABLE) {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "Hashtable setup with user attributes");
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, hashtable);
		}
		return hashtable;
	}

	/**
	 * Verifies the jwtToken and converts its payload to a JSON object.
	 * @param jwtToken contains a signed jwt token
	 * @return the
	 * @throws LoginException if the jwt token verification failed
	 */
	private JSONObject getUserDataFromJwtToken(String jwtToken) throws LoginException{
		final String METHOD_NAME = "getUserDataFromJwtToken(String)";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME, jwtToken);
		JSONObject userInfo = null;
		JwtClaims jwtClaims = null;

		if(httpsJkws == null){
			initializeJwkEndpoint();
		}
		HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

		JwtConsumer jwtConsumer = new JwtConsumerBuilder()
		.setSkipAllValidators()
		.setVerificationKeyResolver(httpsJwksKeyResolver) // verify the signature with the public key
		.build();

		try{
			//  Validate the JWT and process it to the Claims
			jwtClaims = jwtConsumer.processToClaims(jwtToken);
			if(IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "JWT Validation succeded");
		} catch (InvalidJwtException e) {
			LOGGER.logp(Level.WARNING, LOGGER_CLASS, METHOD_NAME, e.getMessage(), e);
			throw new LoginException(e.getMessage());
		}

		try{
			String jsonUserInfo = jwtClaims.getRawJson();
			userInfo = JSONObject.parse(jsonUserInfo);
		}catch (IOException e) {
			LOGGER.logp(Level.WARNING, LOGGER_CLASS, METHOD_NAME, e.getMessage(), e);
			throw new LoginException(e.getMessage());
		}

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, userInfo);
		return userInfo;
	}

	/**
	 * Initializes {@link #httpsJkws} with the value of the {@link #NAME_JWK_ENDPOINT_URL}
	 * property of the jaas login module
	 * @throws LoginException if the value of the {@link #NAME_JWK_ENDPOINT_URL} is not found or empty
	 */
	private void initializeJwkEndpoint() throws LoginException{
		final String METHOD_NAME = "initializeJwkEndpoint()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);
		String jwkEndpointUrl = (String) currentOptions.get(NAME_JWK_ENDPOINT_URL);
		if(jwkEndpointUrl != null && !jwkEndpointUrl.isEmpty()){
			httpsJkws = new HttpsJwks(jwkEndpointUrl);
		}else{
			final String errorMsg = "Jwk Endpoint Url not found in module properties";
			LOGGER.logp(Level.WARNING, LOGGER_CLASS, METHOD_NAME, errorMsg);
			if(IS_LOGGABLE)
				LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, errorMsg);
			throw new LoginException(errorMsg);
		}
		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME);


	}

	/**
	 * Sets the value for the static variable idpSuffix from the currentOptions
	 */
	private void setIdpSuffix() {
		final String METHOD_NAME = "setIdpSuffix()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		idpSuffix = (String) currentOptions.get(TRANSIENT_IDP_SUFFIX_KEY);
		// if not set or null use defaults for backward compatibility reasons
		if ((idpSuffix == null) || (idpSuffix.equals(""))) {
			idpSuffix = TRANSIENT_IDP_SUFFIX_DEFAULT;
		}

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "idpSuffix: " + idpSuffix);
	} // setIdpSuffix

	/**
	 * Sets the value for the static variable providerSuffix from the currentOptions
	 */
	private void setProviderSuffix() {
		final String METHOD_NAME = "setProviderSuffix()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		providerSuffix = (String) currentOptions.get(TRANSIENT_PROVIDER_SUFFIX_KEY);
		// if not set or null use defaults for backward compatibility reasons
		if ((providerSuffix == null) || (providerSuffix.equals(""))) {
			providerSuffix = TRANSIENT_PROVIDER_SUFFIX_DEFAULT;
		}

		providerSuffix= "o=" + providerSuffix;
		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "providerSuffix: " + providerSuffix);
	} // setIdpSuffix

	/**
	 * Sets the name of the group claim in the JWT
	 */
	private void setGroupClaimName() {
		final String METHOD_NAME = "setGroupClaimName()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		groupClaimName = (String) currentOptions.get(GROUP_CLAIM_NAME_KEY);
		// if not set or null use defaults for backward compatibility reasons
		if ((groupClaimName == null) || (groupClaimName.equals(""))) {
			groupClaimName = GROUP_CLAIM_NAME_DEFAULT;
		}

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "groupClaimName: " + groupClaimName);
	} // setGroupClaimName

	/**
	 * Sets the java String.format compatible string to build the groups DN
	 */
	private void setGroupDnFormatString() {
		final String METHOD_NAME = "setGroupDnFormatString()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		groupDnFormatString = (String) currentOptions.get(GROUP_DN_FORMAT_STRING_KEY);
		// if not set or null use defaults for backward compatibility reasons
		if ((groupDnFormatString == null) || (groupDnFormatString.equals(""))) {
			groupDnFormatString = GROUP_DN_FORMAT_STRING_DEFAULT;
		}

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "groupDnFormatString: " + groupDnFormatString);
	} // setGroupDnFormatString

	/**
	 * Converts the JSONArry for the groups to an ArrayList
	 */
	private ArrayList<String> convertJSONArrayToStringArrayList(JSONArray jsonArray) {
		final String METHOD_NAME = "convertJSONArrayToStringArrayList()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		ArrayList<String> stringArrayList = new ArrayList<String>();
		String tmpStr02 = new String();
		int listIndex = 0;

		for( Object groupEntry : jsonArray) {
			 tmpStr02 = MessageFormat.format(groupDnFormatString, groupEntry.toString().trim());
			if(IS_LOGGABLE)
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("tmpStr02 = '%s'", tmpStr02));
			stringArrayList.add(listIndex, tmpStr02);
			listIndex++;
		}

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, String.format("groupDnFormatString: '%s' ; Number of array entries: '%d'",  groupDnFormatString, stringArrayList.size()));
		return stringArrayList;
	} // convertJSONArrayToStringArrayList
}
