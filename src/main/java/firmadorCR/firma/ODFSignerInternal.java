package firmadorCR.firma;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang.ArrayUtils;

import model.Core.be.fedict.eid.applet.service.signer.DigestAlgo;
import model.Core.be.fedict.eid.applet.service.signer.facets.RevocationDataService;
import model.Core.be.fedict.eid.applet.service.spi.DigestInfo;
import model.Core.be.fedict.eid.applet.service.spi.SignatureServiceEx;
import model.Core.be.fedict.eid.dss.document.odf.ODFDSSDocumentService;
import model.JC.JCHiloCargar;
import model.JC.JCSigner;
import model.JC.JCTSPTimeStamService;
import model.JC.JCTrustServiceRevacationDataService;
import model.JC.JCTrustServiceTimeStamServiceValidator;

public class ODFSignerInternal extends JCSigner {

	  public boolean signerDocumento(String resourceName, String rutaFileSalida,
			  List<X509Certificate> chain, KeyPair keypair, 
			  String rol, JCHiloCargar hiloCargar) throws URISyntaxException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
			  {
			    RevocationDataService revocationDataService = new JCTrustServiceRevacationDataService();
			    hiloCargar.setDato("Comprobando valores de revocacion");
			    
			    boolean isRevocado = true;
			    
			    isRevocado = isCertificadoRevocado(chain, hiloCargar);
			    
			    if (!isRevocado) {
			      hiloCargar.setDato("Cargando servicios...");
			      

			      JCTrustServiceTimeStamServiceValidator timeStamServiceValidator = new JCTrustServiceTimeStamServiceValidator();
			      JCTSPTimeStamService timeStamService = new JCTSPTimeStamService(timeStamServiceValidator);
			      

			      boolean isConexionTSA = conectarTSA();
			      
			      if (isConexionTSA)
			      {
			        URL url = new URL(resourceName);
			        File archivo = new File(url.toURI());
			        hiloCargar.setDato("Creando nuevo archivo para firmar...");
			        impress("JC JCSigner :: signerDocumento >> Direcctorio a guardar archivo: " + resourceName);
			        InputStream is = url.openStream();
			        			        
			        OutputStream outputStream = new FileOutputStream(rutaFileSalida);
			        ODFDSSDocumentService oDFDSSDocumentService = new ODFDSSDocumentService();
			        hiloCargar.setDato("Configurando servcicio DSS...");
			        SignatureServiceEx signatureServiceEx = null;
			        try
			        {
			          signatureServiceEx = oDFDSSDocumentService.getSignatureService(is, timeStamService, timeStamServiceValidator, revocationDataService, null, outputStream, rol, null, null, DigestAlgo.SHA1);
			        }
			        catch (Exception ex)
			        {
			          hiloCargar.setDato("Error al obtener servicio DSS...");
			          impress("JC JCSigner :: signerDocumento >> Error al tratar de obtener el servicio DSS\n" + ex.getMessage());
			          return false;
			        }
			        

			        hiloCargar.setDato("Aplicando pre Firma...");
			        DigestInfo digestInfo = signatureServiceEx.preSign(null, chain);
			        hiloCargar.setDato("Generando cipeado RSA/ECB/PKCS1Padding");
			        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			        

			        PrivateKey privateKey = keypair.getPrivate();
			        
			        hiloCargar.setDato("Comprimiendo archivos...");
			        cipher.init(1, privateKey);
					byte[] digestInfoValue = ArrayUtils.addAll(SHA1_DIGEST_INFO_PREFIX, digestInfo.digestValue);
			        byte[] signatureValue = cipher.doFinal(digestInfoValue);
			        hiloCargar.setDato("Aplicando posFirma...");
			        


			        hiloCargar.setDato("Aplicando firma Xades X-L...");
			        signatureServiceEx.postSign(signatureValue, chain);
			        
			        impress("JC JCSigner :: signerDocumento >> El documento firmado se encuentra en: " + rutaFileSalida);
			        
			        hiloCargar.setDato("Finalizando proceso de firma...");
			        return true;
			      }
			      hiloCargar.setDato("No hay conexion con el servicio TSA...");
			      

			      impress("JC JCSigner :: signerDocumento >> No se puede comunicar con la TSA");

			    }
			    else
			    {
			      hiloCargar.setDato("Validez del certificado indefinida");
			      hiloCargar.setRutaArchivoFirmado("podría ser que no hay conexión verifique primero.");
			      impress("JC JCSigner :: signerDocumento >>No se puede definir la validez del certificado, o puede no haber conexion.");
			    }
			    return false;
			  }
	  private void impress(String text)
	  {
	    System.out.println(text);
	  }			  
	
}
