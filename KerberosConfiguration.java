package apache.ds.setup;

import java.util.HashMap;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

public class KerberosConfiguration extends Configuration {
	private final String PATH_TO_KEYTAB = "/etc/krb5.keytab";
    private String principal;

    public KerberosConfiguration() {
    	
    }
    
    public KerberosConfiguration(String principal) {
		 this.principal = principal;
    }
	
	 @Override
     public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
		 HashMap<String, String> options = new HashMap<String, String>();
         options.put("useKeyTab", "true");
         options.put("refreshKrb5Config", "true");
         options.put("principal", principal);
         options.put("keyTab", PATH_TO_KEYTAB);
         return new AppConfigurationEntry[]{
             new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
                                       AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                       options),};
     }	 
}
