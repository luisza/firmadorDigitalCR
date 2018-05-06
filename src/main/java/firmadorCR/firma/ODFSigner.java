package firmadorCR.firma;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.crypto.MarshalException;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.xml.sax.SAXException;
import conexion.ConexionTarjeta;
import conexion.InfoTokenCertificados;
import model.JC.JCHiloCargar;
import util.RespuestaAcceso;

public class ODFSigner {
	JCHiloCargar hiloCargar;
	

	private boolean _sign(String documentpath,  String saveDocumentpath, String pin, String reason) throws KeyStoreException, InvalidKeyException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, MalformedURLException, XMLSignatureException, SAXException, javax.xml.crypto.dsig.XMLSignatureException, MarshalException, ParserConfigurationException, XMLSecurityException, IOException, OCSPException, URISyntaxException{
		ODFSignerInternal signer = new ODFSignerInternal();
    	ConexionTarjeta conexion = new ConexionTarjeta();
    	conexion.mLimpiarListaCertificados();
        
        RespuestaAcceso resCargarInfoTokens = conexion.cargarInfotokenExternos("FIRMA", pin);
        if (!resCargarInfoTokens.isResultado()) {
        	System.exit(1);
            //return resCargarInfoTokens;
          }
          
          KeyPair keyPair = null;
          
          X509Certificate x509Certificate = null;
          List<X509Certificate> chain = null;
          
          ArrayList<InfoTokenCertificados> listaInfoTokenCertificados = null;
          listaInfoTokenCertificados = conexion.getListaInfoTokenCertificados();
          
          for (int i = 0; i < listaInfoTokenCertificados.size(); i++) {
            InfoTokenCertificados infoTokenCertificados = (InfoTokenCertificados)listaInfoTokenCertificados.get(i);
            ArrayList<X509Certificate> listacert = infoTokenCertificados.getListaCertificados();
            
            for (int j = 0; j < listacert.size(); j++) {
              x509Certificate = (X509Certificate)listacert.get(j);
              chain = conexion.getCertificateChain((X509Certificate)listacert.get(j));
              keyPair = conexion.getKeyPair(x509Certificate, infoTokenCertificados.getKey().toCharArray());
            }
          }
          hiloCargar = new JCHiloCargar();
          hiloCargar.setRutaArchivoFirmado("Guardado en :"+saveDocumentpath);
          boolean firmado = signer.signerDocumento(documentpath, saveDocumentpath,
        		  							chain, keyPair, 
        		  							reason, hiloCargar);
          hiloCargar.setIsContinuar(false);
          
          return firmado;
    
	}
	
	public boolean sign(String documentpath, String saveDocumentpath, PasswordProtection pin, String reason){
		boolean ok = false;
		try {
			documentpath=Paths.get(documentpath).toUri().toString();
			ok = this._sign(documentpath, saveDocumentpath,
					String.valueOf(pin.getPassword()), reason);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			ok=false;
		}
		return ok;
	}
	
}
