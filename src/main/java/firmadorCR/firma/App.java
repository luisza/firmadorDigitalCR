package firmadorCR.firma;

import java.security.KeyStore.PasswordProtection;

import cr.fran.gui.GUIInterface;
import cr.fran.gui.GUISelector;

/**
 * Hello world!
 *
 */
public class App 
{
	
	
    public static void main( String[] args )
    {
    	
        GUISelector guiselector = new GUISelector();

        GUIInterface gui = guiselector.getInterface(args);
        gui.setArgs(args);
   	
    	String documentpath=gui.getDocumentToSign();
    	String savedpath=gui.getPathToSave();
        PasswordProtection pin=gui.getPin();
    	String reason = "xq me da la gana";
    	ODFSigner signer = new ODFSigner();
    	boolean b = signer.sign(documentpath,savedpath,  pin, reason);
    	System.out.println(b);
    	System.exit(0);
    }
}
