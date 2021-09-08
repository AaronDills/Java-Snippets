package apache.ds.setup;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class KerberosCallBackHandler implements CallbackHandler {
	
	private char[] password;
	private String username;
	
	public KerberosCallBackHandler() {
		
	}
	
	public KerberosCallBackHandler(String username, char[] password) {
		this.username = username;
		this.password = password;
	}

	 public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
	  for (int i = 0; i < callbacks.length; i++)
	  {
	     Callback c = callbacks[i];
	     if (c instanceof NameCallback)
	     {
	        NameCallback nc = (NameCallback) c;
	        nc.setName(this.username);
	     }
	     else if (c instanceof PasswordCallback)
	     {
	        PasswordCallback pc = (PasswordCallback) c;
	        if( password != null )
	        {
	            pc.setPassword(password);
	
	        }
	     }
	     else
	     {
	        throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
	     }
  }
}
}