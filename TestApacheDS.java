package apache.ds.setup;

import org.apache.directory.ldap.client.api.LdapNetworkConnection;

public class TestApacheDS {

    private LdapConnectionConfig config;
    private LdapNetworkConnection conn;
    private boolean useTls;

    public TestApacheDS(){

    }

    public TestApacheDS(boolean useTls, String username, String password){
        this.useTls = useTls;
        this.config = createLdapConfig();
        this.conn = new LdapNetworkConnection(this.config);
    }

    public static void main(String[] args){

        TestApacheDS test = new TestApacheDS(true);
        test.testLdapBind();
        test.testSmbAuth();
    }

    private boolean testSmbAuth(){
        Connection connection = new SMBClient().connect(config.getLdapHost());
        try {
		    LoginContext lc = new LoginContext("lc", null, new KerberosCallBackHandler(config.getName(), config.getCredentials().toCharArray()), new KerberosConfiguration(config.getName()));
		    lc.login();
		    Subject subject = lc.getSubject();
		    subject = lc.getSubject();
		    KerberosPrincipal kerberosPrincipal = subject.getPrincipals(KerberosPrincipal.class).iterator().next();
		    GSSManager manager = GSSManager.getInstance();
		    GSSName name = manager.createName(kerberosPrincipal.toString(), GSSName.NT_USER_NAME);
		    Oid kerberos5 = new Oid("1.2.840.113554.1.2.2");

		    GSSCredential creds = Subject.doAs(subject, new PrivilegedExceptionAction<GSSCredential>() {
		        @Override
		        public GSSCredential run() throws GSSException {
		            return manager.createCredential(name, GSSCredential.DEFAULT_LIFETIME, kerberos5, GSSCredential.INITIATE_ONLY);
		        }
		    });		    
		    GSSAuthenticationContext auth = new GSSAuthenticationContext(
		    		kerberosPrincipal.getName(),
		    		info.getDomain(),
		            subject,
		            creds
		        );
	        Session session = connection.authenticate(auth);
        }catch(Exception e){

        }
    }

    private boolean testBinding(){
        conn.connect();
        if(useTls){
            ldap.startTls();
        }
        BindResponse resp = conn.bind(generateSaslGssApiRequest());
        org.apache.directory.api.ldap.model.message.ResultCodeEnum.processResponse(resp);
    }

    private LdapConnectionConfig createLdapConfig(InetSocketAddress host) {
		LdapConnectionConfig config = new LdapConnectionConfig();
		config.setLdapHost(host.getHostName());
		config.setLdapPort(host.getPort());
		config.setBinaryAttributeDetector(buildBinaryAttributeDetector());
		if (username != null){
			config.setName(username);
        }
		if (password != null){
			config.setCredentials(password);
        }
		if (trustManagers != null){
			config.setTrustManagers(trustManagers);
        }
		config.setKeyManagers(keyManagers);		
		return config;
	}

    private BinaryAttributeDetector buildBinaryAttributeDetector() {
		DefaultConfigurableBinaryAttributeDetector ret = new DefaultConfigurableBinaryAttributeDetector();
		ret.addBinaryAttribute(BINARY_ATTRIBUTES);
		return ret;
	}
	

    private SaslGssApiRequest generateSaslGssApiRequest() {
		SaslGssApiRequest saslGssApiRequest = new SaslGssApiRequest();
	    saslGssApiRequest.setLoginModuleConfiguration(new KerberosConfiguration(username));
        saslGssApiRequest.setLoginContextName( "org.apache.directory.ldap.client.api.SaslGssApiRequest" );
        saslGssApiRequest.setKrb5ConfFilePath( "/etc/krb5.conf" );
        saslGssApiRequest.setUsername(username);
        saslGssApiRequest.setCredentials(password);
        saslGssApiRequest.setQualityOfProtection(SaslQoP.AUTH_CONF);
        return saslGssApiRequest;
	}


}



	