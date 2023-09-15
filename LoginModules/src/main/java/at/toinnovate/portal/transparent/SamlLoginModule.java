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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.ws.security.core.ContextManagerFactory;
import com.ibm.ws.wssecurity.platform.websphere.wssapi.token.impl.WasSAML20TokenImpl;

import javax.naming.InitialContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

import com.ibm.wsspi.security.token.AttributeNameConstants;
import com.ibm.wsspi.security.auth.callback.WSTokenHolderCallback;
import com.ibm.json.java.JSONArray;
import com.ibm.json.java.JSONObject;
import com.ibm.portal.auth.tai.ExternalIdentityCredential;
import com.ibm.websphere.security.UserRegistry;
import com.ibm.websphere.wim.SchemaConstants;
import com.ibm.websphere.wim.Service;
import com.ibm.websphere.wim.client.LocalServiceProvider;
import com.ibm.websphere.wim.ras.WIMTraceHelper;
import com.ibm.websphere.wim.util.SDOHelper;

import commonj.sdo.DataObject;

import com.ibm.websphere.wssecurity.wssapi.WSSUtilFactory;
import com.ibm.websphere.wssecurity.wssapi.token.SAMLToken;
import com.ibm.wsspi.wssecurity.saml.data.SAMLAttribute;
import com.ibm.wsspi.wssecurity.saml.data.SAMLNameID;

/**
 * @author hhuebler@2innovate.at
 *
 */
public class SamlLoginModule implements LoginModule {
	private static final String LOGGER_CLASS = SamlLoginModule.class.getName();
	private static final Logger LOGGER = Logger.getLogger(LOGGER_CLASS);
	private static final Level LOG_LEVEL = Level.FINE;

	private static final String SAML_TENANTID_ATTRIBUTE = "http://schemas.microsoft.com/identity/claims/tenantid";
	private static final String SAML_OBJECTID_ATTRIBUTE = "http://schemas.microsoft.com/identity/claims/objectidentifier";
	private static final String SAML_DISPLAY_NAME_ATTRIBUTE = "http://schemas.microsoft.com/identity/claims/displayname";
	private static final String SAML_IDENTITY_PROVIDER_ATTRIBUTE = "http://schemas.microsoft.com/identity/claims/identityprovider";
	private static final String SAML_AUTHENTICATION_METHOD_REFERNCE_ATTRIBUTE = "http://schemas.microsoft.com/claims/authnmethodsreferences";
	private static final String SAML_GIVENNAME_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
	private static final String SAML_SURNAME_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";
	private static final String SAML_NAME_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";

	private static final String DEFAULT_REALM_NAME_DEFAULT = "defaultWIMFileBasedRealm";
	private static final String DEFAULT_REALM_NAME_KEY = "default.realm.name";
	private static final String EMAIL_DOMAIN_DEFAULT = "mail.org";
	private static final String EMAIL_DOMAIN_KEY = "email.domain";
	// transientidp.basedn.suffix must match the base entry of the transientidp repository in the VMM
	private static final String TRANSIENT_IDP_SUFFIX_DEFAULT = "o=transparent";
	private static final String TRANSIENT_IDP_SUFFIX_KEY = "transientidp.basedn.suffix";
	// transientidp.vp.suffix must match buildgroupsfor value! For example o=base
	private static final String TRANSIENT_PROVIDER_SUFFIX_DEFAULT = "base";
	private static final String TRANSIENT_PROVIDER_SUFFIX_KEY = "transientidp.buildgroupsfor";
	// static variables taken from the module config
	private static String defaultRealmName = null;
	private static String transientEMailDomain = null;
	private static String idpSuffix = null;
	private static String providerSuffix = null;

	private boolean success = false;
	private Subject currentSubject;
	private CallbackHandler currentCallbackHandler;
	private Map<String, Object> currentSharedState;
	private Map<String, Object> currentOptions;

	private static Properties getPropsFromFileLoaded  (String fileName) {
		final String METHOD_NAME = "getPropsFromFileLoaded()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if (IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		FileInputStream propFile = null;
		Properties prop = new Properties();

		try {
			propFile = new FileInputStream(fileName);
			prop.load(propFile);
			LOGGER.exiting(LOGGER_CLASS, "getPropsFromFileLoaded - with props");
			return prop;
		} catch (IOException ex) {
			ex.printStackTrace();
			LOGGER.finer("Loading properties from file " + fileName + "failed with exception:\n" + ex.getStackTrace().toString());
		} finally {
			if (propFile != null) {
				try {
					propFile.close();
				} catch (IOException e) {
					e.printStackTrace();
					LOGGER.finer("Closing properties from file " + fileName + "failed with exception:\n" + e.getStackTrace().toString());
				}
			}
		}
		if (IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "return null");
		return null;
	}


	private static Hashtable<String, String> getGroupMappings  (final Properties loginModuleProps) {
		final String METHOD_NAME = "getGroupMappings()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if (IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		String propKey = null;
		String userPrefix = null;
		String prefixGroupName = null;
		Hashtable<String, String> rtnTable = new Hashtable<String, String>();

		int MAX_PROPS_INDEX = 99;
		if (loginModuleProps != null) {
			int propIndex = 0;
			while (propIndex <= MAX_PROPS_INDEX) {
				propKey = "transparent.user.prefix." + Integer.toString(propIndex);
				if (loginModuleProps.getProperty(propKey) != null) {
					userPrefix = loginModuleProps.getProperty(propKey);
					LOGGER.fine(Integer.toString(propIndex) + ". userPrefix: " + userPrefix);
					propKey = "transparent.group.name." + Integer.toString(propIndex);
					if (loginModuleProps.getProperty(propKey) != null) {
						prefixGroupName = loginModuleProps.getProperty(propKey);
						LOGGER.fine(Integer.toString(propIndex) + ". prefixGroupName: " + prefixGroupName);
						rtnTable.put(userPrefix, prefixGroupName);
					} else {
						LOGGER.fine(Integer.toString(propIndex) + ". prefixGroupName: is NULL!!");
					}
				}
				propIndex++;
			}

			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "getPropsFromFile - return hashtable with # entries: " + Integer.toString(rtnTable.size()));
			return rtnTable;
		} else {
			if (IS_LOGGABLE)
				LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "getPropsFromFile - return null");
			return null;
		}
	}


public interface UniqueNameAccessor {
		String getUniqueName(String email, String useVP) throws Exception;
	}

public static final class UniqueNameAccessorImpl implements UniqueNameAccessor {
	private static final String LOGGER_CLASS = UniqueNameAccessorImpl.class.getName();
	private static final Logger LOGGER = Logger.getLogger(LOGGER_CLASS);
	String uniqueName = "";

	@SuppressWarnings("unchecked")
	private List<DataObject> getDoListForUser (final Service service, final DataObject root, final String email) throws Exception {
		final String METHOD_NAME = "getDoListForUser()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if (IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		DataObject searchCtrl = SDOHelper.createControlDataObject(root, null, SchemaConstants.DO_SEARCH_CONTROL);
		searchCtrl.getList(SchemaConstants.PROP_PROPERTIES).add("dn");
		searchCtrl.getList(SchemaConstants.PROP_PROPERTIES).add("uniqueName");
		searchCtrl.getList(SchemaConstants.PROP_PROPERTIES).add("mail");
		//search for mail or uid - because e.g. the "wpsadmin" login still needs to work
		// searchCtrl.setString(SchemaConstants.PROP_SEARCH_EXPRESSION, "@xsi:type='PersonAccount' and ( mail='"+email+"' or uid='"+email+"')");
		searchCtrl.setString(SchemaConstants.PROP_SEARCH_EXPRESSION, "@xsi:type='PersonAccount' and ( uid='"+email+"')");
		if (IS_LOGGABLE)
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("searchCtrl: '%s'", searchCtrl.getString(SchemaConstants.PROP_SEARCH_EXPRESSION).toString()));

		DataObject searchRoot = service.search(root);
		if (IS_LOGGABLE)
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Output 1. search: '%s'", WIMTraceHelper.printDataObject(searchRoot)));

		List<DataObject> entities = searchRoot.getList(SchemaConstants.DO_ENTITIES);
		// Nothing found ... repeat search with eMail
		if (entities.size()==0) {
			searchCtrl.setString(SchemaConstants.PROP_SEARCH_EXPRESSION, "@xsi:type='PersonAccount' and ( mail='"+email+"')");
			searchRoot = service.search(root);
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Output 2. search: '%s'", WIMTraceHelper.printDataObject(searchRoot)));
			entities = searchRoot.getList(SchemaConstants.DO_ENTITIES);
		}
		if (IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME,  String.format("Number of entries in DO list: '%d'", entities.size()));
		return entities;
	}

	@Override
	public String getUniqueName(final String email, final String useVP) throws Exception {
		final String METHOD_NAME = "getUniqueName()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE) {
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("getUniqueName - eMail + useVP: '%s' + '%s'", email, useVP));
		}

		PrivilegedExceptionAction<Void> action = new PrivilegedExceptionAction<Void>() {
			@Override
			public Void run() throws Exception {
				LOGGER.entering(LOGGER_CLASS, "getUniqueName");
				final String METHOD_NAME = "getUniqueName()";
				final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);
				if (IS_LOGGABLE)
					LOGGER.entering(LOGGER_CLASS, "run");
				Service service = new LocalServiceProvider();
				DataObject root = SDOHelper.createRootDataObject();
				if (!useVP.equals(defaultRealmName)) {
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Non-defaultWIMFileBasedRealm case! UseRealm: '%s'", useVP));
					DataObject context = root.createDataObject(Service.DO_CONTEXTS);
					context.set(Service.PROP_KEY, Service.VALUE_CONTEXT_REALM_KEY);
					context.set(Service.PROP_VALUE, useVP);
				}

				List entities = getDoListForUser (service, root, email);
				LOGGER.fine("Entities.size: " + entities.size());
				// if no users found .. try eMail
				if (entities.size()==1) {
					LOGGER.fine("Only one match in searchScope!");
						DataObject ent = (DataObject) entities.get(0);
						DataObject id = ent.getDataObject(SchemaConstants.DO_IDENTIFIER);
						if (id != null) {
							uniqueName = id.getString(SchemaConstants.PROP_UNIQUE_NAME);
							LOGGER.fine("UniqueName is:  " +uniqueName);
						} else {
							LOGGER.fine("id not found - throw exception; will be handled as transient user");
							//will get handled as transient user
							LOGGER.fine("run; id not found exception thrown");
							throw new Exception();
						}
				} else {
					LOGGER.fine("run; entities are null or multiple - throw exception; will be handled as transient user");
					//will get handled as transient user
					throw new Exception();
				}
				if (IS_LOGGABLE)
					LOGGER.exiting(LOGGER_CLASS, "run; returning null");
				return null;
			}
		};
		ContextManagerFactory.getInstance().runAsSystem(action);
		if (IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, "getUniqueName; uniqueName: " +uniqueName);
		return uniqueName;
	}
}


	@SuppressWarnings("unchecked")
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
		final String METHOD_NAME = "initialize()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		currentSubject = subject;
		currentCallbackHandler = callbackHandler;
		currentSharedState = (Map<String, Object>) sharedState;
		currentOptions = (Map<String, Object>) options;
		success = false;

		if (IS_LOGGABLE) {
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentSubject: '%s'", currentSubject.toString()));
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentCallbackHandler: '%s'", currentCallbackHandler.toString()));
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentSharedState: '%s'", currentSharedState.toString()));
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentOptions: '%s'", currentOptions.toString()));
			traceSAMLTokens(currentSubject);

		}

		// initialize the static variables for the idp and provider suffix
		if (defaultRealmName == null) {
			setDefaultRealmName();
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("defaultRealmName set to: '%s'", defaultRealmName));
		}

		if (transientEMailDomain == null) {
			setTransientEMailDomain();
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("transientEMailDomain set to: '%s'", transientEMailDomain));
		}

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

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, "SamlLoginModule initialize");
	}

	private ArrayList<String> getGroupList (ArrayList <String> groupList, final Hashtable groupMappings, String username) {
		LOGGER.entering(LOGGER_CLASS, "getGroupList");
		// Check if the user belongs to a group and add user to groups
		// (groupmembership depends on the start String in the user name
		Iterator<String> mappingsIterator = groupMappings.keySet().iterator();
		if (mappingsIterator.hasNext()) {
			while (mappingsIterator.hasNext()) {
				String hashKey = mappingsIterator.next();
				if (username.startsWith(hashKey)) {
					LOGGER.fine("Added user to group: " + (String) groupMappings.get(hashKey));
					groupList.add((String) groupMappings.get(hashKey));
				}

			}
		} else {
			LOGGER.fine("No entries in mappingsIterator");
		}
		LOGGER.fine("Number of entries in the group list: " + Integer.toString(groupList.size()));

		LOGGER.exiting(LOGGER_CLASS, "getGroupList");
		return groupList;
	}
	@Override
	public boolean login() throws LoginException {
		final String METHOD_NAME = "login()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if (IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);
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
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "requires login? : {0}", new Object[]{requiresLogin});
			// check if login at all is required correct position in queue)
			if (requiresLogin) {

				String username = ((NameCallback) callbacks[0]).getName();
				if (username != null) {
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("username is: '%s' ", username));
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
						if (o != null && o instanceof Hashtable<?, ?>) {
							if (IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "hashtable casted from WSCREDENTIAL_PROPERTIES_KEY");
							hashtable = (Hashtable<String, Object>) o;
						} else {
							if (IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "created new hashtable");
							hashtable = new Hashtable<String, Object>();
						}

						hashtable = mapUserAttributesToHashtable(username, hashtable, currentSubject);
						if (IS_LOGGABLE)
							LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "adding uniqueid to WSCREDENTIAL_UNIQUEID+WSCREDENTIAL_SECURITYNAME ");
						hashtable.put(AttributeNameConstants.WSCREDENTIAL_UNIQUEID, uniqueid);
						hashtable.put(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME, uniqueid);
						if (IS_LOGGABLE)
							LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "added uniqueid to WSCREDENTIAL_UNIQUEID+WSCREDENTIAL_SECURITYNAME ");

						currentSubject.getPublicCredentials().add(hashtable);
						currentSubject.getPublicCredentials().add(new ExternalIdentityCredential(hashtable));
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
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("uniqueid: '%s'", uniqueid));
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
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("success with uniqueid: '%s'", uniqueid));

		} else {
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("failed with uniqueid: '%s'", uniqueid));
		}

		if (IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, success);
		return success;

	}

/**
	public boolean login2() throws LoginException {

		final String METHOD_NAME = "login()";
		if (IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);
		String uniqueid = "";
		String currentVP = defaultRealmName;
		if (IS_LOGGABLE) {
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentVP set to: '%s'", currentVP));
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("transientEMailDomain set to: '%s'", transientEMailDomain));
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("private credentials are: '%s'", currentSubject.getPrivateCredentials().getClass().toString()));
		}
		//get specified realm property on SAML TAI
		//use sso_1.sp.cookieGroup
		Iterator<Object> it2 = currentSubject.getPrivateCredentials().iterator();
		if(it2.hasNext()) {
			Object actual = it2.next();
			Hashtable<String, String> myHash = (Hashtable<String, String>)actual;
			if (IS_LOGGABLE) {
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("actual private credential '%s'", actual.getClass().toString()));
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("myHash '%s'", myHash.toString()));
			}
			try {
	//			currentVP = (String)myHash.get(com.ibm.wsspi.security.token.AttributeNameConstants.WSCREDENTIAL_REALM);
	//			currentVP = (String)myHash.get("com.ibm.wsspi.security.cred.realm");
				String getScope = (String)myHash.get("Saml20TaiSsoPartners");
				if (IS_LOGGABLE)
					LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Got scope: '%s'", getScope));
				if (getScope!=null) {
					int position = getScope.lastIndexOf("_");
					if ((position+1)<getScope.length()) {
						currentVP = getScope.substring(position+1);
						if (IS_LOGGABLE) {
							LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Saml20TaiSsoPartners set: '%s'", getScope));
							LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentVP set: '%s'", currentVP));
						}
					}
				}
				//null if the current user is a idAssert case.
			} catch (Exception ex1) {
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("error with com.ibm.wsspi.security.cred.realm. Exception '%s'", ex1.toString()));
			}
		} // it2.hasNext

		if (IS_LOGGABLE)
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentVP before check: '%s'", currentVP));
		if (currentVP.startsWith("http")) {
			currentVP = defaultRealmName;
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentVP starts with http -> set to default: '%s'", currentVP));
		}
		if (currentVP.equals("")) {
			currentVP = defaultRealmName;
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("currentVP not set -> set to detault: '%s'", currentVP));
		}
		LOGGER.fine("currentVP cleaned: "+currentVP);

		Hashtable<String,Object> hashtable = new Hashtable();
		Callback callbacks[] = new Callback[3];
		ArrayList<String> groupList = new ArrayList<String>();

		try {
			callbacks[0] = new WSTokenHolderCallback("");
			callbacks[1] = new NameCallback("User:");
			callbacks[2] = new PasswordCallback("Password:", false);
			currentCallbackHandler.handle(callbacks);

			boolean requiresLogin = ((WSTokenHolderCallback) callbacks[0]).getRequiresLogin();
			//check if login at all is required correct position in queue)
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("requires login: '%s'", Boolean.toString(requiresLogin)));
			if (requiresLogin) {
				String username = ((NameCallback) callbacks[1]).getName();
				if (username != null) {
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("username: '%s'", username));
					try {
						String userUniqueName = new UniqueNameAccessorImpl().getUniqueName(username, currentVP);
						if (userUniqueName != null) {
							if (IS_LOGGABLE)
								LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("userUniqueName: '%s'", userUniqueName));
							uniqueid = userUniqueName;
							//set DN to make sure the following flow works with THIS user in defined realm
							hashtable.put(AttributeNameConstants.WSCREDENTIAL_UNIQUEID, userUniqueName);
							hashtable.put(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME, userUniqueName);
							currentSubject.getPublicCredentials().add(hashtable);
							currentSharedState.put(AttributeNameConstants.WSCREDENTIAL_PROPERTIES_KEY, hashtable);
						} else {
							LOGGER.logp(Level.SEVERE, LOGGER_CLASS, METHOD_NAME, "userUniqueName is NULL");
							throw new Exception();
						}
					} catch (Exception e) {
						if (IS_LOGGABLE) {
							LOGGER.fine("error in VMM lookup "+e);
							LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("error in VMM lookup: '%s'", e));
							LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "Login Module - User was not found by realm scoped VMM search -> must be transient");
						}
						//user was not found by realm scoped VMM search -> must be transient
						//create realmScoped DN to support transient AC-groups
						//Global security > Federated repositories > transientidp : buildgroupsfor = <vpscopeName1>  <vpscopeName2>
						if (!currentVP.equals(defaultRealmName)) {
							//VP scope available, scope transient group to this
							if (IS_LOGGABLE)
								LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Login Module - transient for non-default realm: '%s'", currentVP));
							uniqueid = String.format("uid=%s,%s,%s", username, providerSuffix, idpSuffix);

							if (IS_LOGGABLE)
								LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("transient for VPScope - uniqueid: '%s'", uniqueid));
						} else {
							//no VP scope but transient for base
							if (IS_LOGGABLE)
								LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Login Module - transient for DEFAULT realm: '%s'", currentVP));
							uniqueid = String.format("uid=%s,o=%s,%s", username, defaultRealmName, idpSuffix);
							if (IS_LOGGABLE)
								LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("transient for base - uniqueid: '%s'", uniqueid));
						}
						hashtable.put(AttributeNameConstants.WSCREDENTIAL_UNIQUEID, uniqueid);
						hashtable.put(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME, uniqueid);
						// You may add specific users to specific groups to not only have all transient user as "AllAuthenticated"
						if (username.equals("wpsadmin") || username.equals("wpadmin")) {
							if (IS_LOGGABLE)
								LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "Adding user to administrators group");
							groupList.add("cn=wpsadmins,o=defaultWIMFileBasedRealm");
							// Add attributes for this special user as well
						}

						hashtable.put("sn",username + "-sn");
						hashtable.put("cn",username + "-cn");
						hashtable.put("uid",username);
						if (username.indexOf("@") >= 0)
							hashtable.put("ibm-primaryEmail",username);
						else
							hashtable.put("ibm-primaryEmail",username+"@" + transientEMailDomain);

						// Add the groups from the properties to the group list
						// groupList = getGroupList (groupList, groupMappings, username);
						// hashtable.put(AttributeNameConstants.WSCREDENTIAL_GROUPS,groupList);
						currentSubject.getPublicCredentials().add(hashtable);
						currentSubject.getPublicCredentials().add(new ExternalIdentityCredential(hashtable));
						currentSharedState.put(AttributeNameConstants.WSCREDENTIAL_PROPERTIES_KEY, hashtable);
					}

					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("username <> null; uniqueid: '%s'", uniqueid));
				} else {
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "uniqueid is null --> do nothing");
					success = false;
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("failed with uniqueid: '%s'", uniqueid));
					return success;
				}
			} else {
				if (IS_LOGGABLE)
					LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "seems to be a repeat login, nothing to do!");
				try {
					String username = ((NameCallback) callbacks[1]).getName();
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("No login required for user: '%s'", username));
				}
				catch (Exception ex) {
					if (IS_LOGGABLE)
						LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Trying to retrieve user name for repeated login failed with: '%s'", ex));
				}
			}

		} catch (Exception e) {
			if (IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Login Module failed: '%s'", e));
		}
		success = true;
		LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, String.format("success with uniqueid: '%s'", uniqueid));
		return success;
	}
*/
	@Override
	public boolean commit() throws LoginException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean abort() throws LoginException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean logout() throws LoginException {
		// TODO Auto-generated method stub
		return false;
	}
	/**
	 * Sets the value for the static variable defaultRealmName from the currentOptions
	 */
	private void setDefaultRealmName() {
		final String METHOD_NAME = "setDefaultRealmName()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		defaultRealmName = (String) currentOptions.get(DEFAULT_REALM_NAME_KEY);
		// if not set or null use defaults for backward compatibility reasons
		if ((defaultRealmName == null) || (defaultRealmName.equals(""))) {
			defaultRealmName = DEFAULT_REALM_NAME_DEFAULT;
		}

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "defaultRealmName: " + defaultRealmName);
	} // setDefaultRealmName
	/**
	 * Sets the value for the static variable transientEMailDomain from the currentOptions
	 */
	private void setTransientEMailDomain() {
		final String METHOD_NAME = "setTransientEMailDomain()";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		transientEMailDomain = (String) currentOptions.get(EMAIL_DOMAIN_KEY);
		// if not set or null use defaults for backward compatibility reasons
		if ((transientEMailDomain == null) || (transientEMailDomain.equals(""))) {
			transientEMailDomain = EMAIL_DOMAIN_DEFAULT;
		}

		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, "transientEMailDomain: " + transientEMailDomain);
	} // setTransientEMailDomain
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


	private String convertStreamToString(InputStream is) {
		String rtnString;
		Scanner s = new Scanner(is).useDelimiter("\\A");

		try {
			rtnString = s.hasNext() ? s.next() : "";
		} finally {
			s.close();
		}
		return rtnString;
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
			LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, "size of private credential set is {0},", new Object[] {cred.size()});
		Iterator<Object> iterator = cred.iterator();
		while(iterator.hasNext()){
			Object o =iterator.next();
			if(IS_LOGGABLE)
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("Class of private credemtial: '%s'", o.getClass().getName()));
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
 * https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.multiplatform.doc/ae/rwbs_libraryapisaml.html#rwbs_libraryapisaml__map
 * @param username
 * @param hashtable
 * @param subject
 * @return
 */
	private Hashtable<String, Object> mapUserAttributesToHashtable(String username, Hashtable<String, Object> hashtable, Subject subject) {
		final String METHOD_NAME = "mapUserAttributesToHashtable(String, Hashtable, Subject)";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		String hashKey = "";

		hashtable.put("uid", username);
		// Copy the SAML Attributes
		Set<SAMLToken> samlTokenSet = currentSubject.getPrivateCredentials(SAMLToken.class);
		for (SAMLToken samlToken : samlTokenSet) {
			List<SAMLAttribute> allAttributes = samlToken.getSAMLAttributes();
			if (allAttributes.isEmpty()) {
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "No SAML attribute found");
			} else {
				for (SAMLAttribute anAttribute : allAttributes) {
					String attributeName = anAttribute.getName();
					String[] attributeValues = anAttribute.getStringAttributeValue();
					String value = null;
					if(attributeValues.length == 1) {
						value = attributeValues[0];
					} else if(attributeValues.length == 0) {
						value = "no value";
					} else {
						StringBuilder sb = new StringBuilder("[");
						for(int i = 0; i < attributeValues.length; i++) {
							sb.append(attributeValues[i]);
							sb.append(", ");
						}
						sb.append("]");
						value = sb.toString();
					}

					switch (attributeName) {
						case SAML_DISPLAY_NAME_ATTRIBUTE:
							hashKey = "cn";
							hashtable.put(hashKey, value);
							if(IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("Added attribute: '%s' with value: '%s' to hashtable", hashKey, value));
							hashKey = "displayName";
							hashtable.put(hashKey, value);
							if(IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("Added attribute: '%s' with value: '%s' to hashtable", hashKey, value));
							break;
						case SAML_GIVENNAME_ATTRIBUTE:
							hashKey = "givenName";
							hashtable.put(hashKey, value);
							if(IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("Added attribute: '%s' with value: '%s' to hashtable", hashKey, value));
							break;
						case SAML_SURNAME_ATTRIBUTE:
							hashKey = "sn";
							hashtable.put(hashKey, value);
							if(IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("Added attribute: '%s' with value: '%s' to hashtable", hashKey, value));
							break;
						case SAML_NAME_ATTRIBUTE:
							hashKey = "ibm-primaryEmail";
							hashtable.put(hashKey, value);
							if(IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("Added attribute: '%s' with value: '%s' to hashtable", hashKey, value));
							break;
						default:
							if(IS_LOGGABLE)
								LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("SAML attribute: '%s' not processed for hashtable", attributeName));
					} // case
				}
			}
		}

		if(IS_LOGGABLE) {
			LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, String.format("Hashtable setup with user attributes: '%s'", hashtable));
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME, hashtable);
		}
		return hashtable;
	}

/**
 * https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.multiplatform.doc/ae/rwbs_libraryapisaml.html#rwbs_libraryapisaml__map
 * @param currentSubject
 */
	private void traceSAMLTokens(Subject currentSubject) {
		final String METHOD_NAME = "traceSAMLTokens(currentSubject)";
		final boolean IS_LOGGABLE = LOGGER.isLoggable(LOG_LEVEL);

		if(IS_LOGGABLE)
			LOGGER.entering(LOGGER_CLASS, METHOD_NAME);

		Set<SAMLToken> samlTokenSet = currentSubject.getPrivateCredentials(SAMLToken.class);
		for (SAMLToken samlToken : samlTokenSet) {
			List<SAMLAttribute> allAttributes = samlToken.getSAMLAttributes();
			if (allAttributes.isEmpty()) {
				LOGGER.logp(Level.FINEST, LOGGER_CLASS, METHOD_NAME, "No SAML attribute found");
				return;
			}
			for (SAMLAttribute anAttribute : allAttributes) {
				String attributeName = anAttribute.getName();
				String[] attributeValues = anAttribute.getStringAttributeValue();
				String value = null;
				if(attributeValues.length == 1) {
					value = attributeValues[0];
				} else if(attributeValues.length == 0) {
					value = "no value";
				} else {
					StringBuilder sb = new StringBuilder("[");
					for(int i = 0; i < attributeValues.length; i++) {
						sb.append(attributeValues[i]);
						sb.append(", ");
					}
					sb.append("]");
					value = sb.toString();
				}
				LOGGER.logp(LOG_LEVEL, LOGGER_CLASS, METHOD_NAME, String.format("SAML attribute name: '%s' value: '%s'", attributeName, value));
			}
		}
		if(IS_LOGGABLE)
			LOGGER.exiting(LOGGER_CLASS, METHOD_NAME);
	} // traceSAMLTokens


}
