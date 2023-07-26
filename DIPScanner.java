import java.io.*;
import java.net.*;
import javax.net.ssl.*;

public class DIPScanner{

	private static final String protocol="https://",
			     				  domain="?";
	private static final byte[] 	word="?".getBytes();
	private static final int 	 threads=4096,
							 	 timeout=2048,
							 	 content=256;

	static{

		System.setProperty("sun.net.http.allowRestrictedHeaders","true");

		HttpsURLConnection.setDefaultHostnameVerifier(

			new HostnameVerifier(){

				public boolean verify(String hostname, SSLSession session){

					return true;

				}

			}

		);

	}

	private static int nip=0xFF_FF_FF_FF;
	private static synchronized String nextIP(){

		nip++;

			 if(nip==0x00_00_00_00)nip=0x00_FF_FF_FF+1;
		else if(nip==0x0A_00_00_00)nip=0x0A_FF_FF_FF+1;
		else if(nip==0x64_40_00_00)nip=0x64_7F_FF_FF+1;
		else if(nip==0x7F_00_00_00)nip=0x7F_FF_FF_FF+1;
		else if(nip==0xA9_FE_00_00)nip=0xA9_FE_FF_FF+1;
		else if(nip==0xAC_10_00_00)nip=0xAC_1F_FF_FF+1;
		else if(nip==0xC0_00_00_00)nip=0xC0_00_00_FF+1;
		else if(nip==0xC0_00_02_00)nip=0xC0_00_02_FF+1;
		else if(nip==0xC0_58_63_00)nip=0xC0_58_63_FF+1;
		else if(nip==0xC0_A8_00_00)nip=0xC0_A8_FF_FF+1;
		else if(nip==0xC6_12_00_00)nip=0xC6_13_FF_FF+1;
		else if(nip==0xC6_33_64_00)nip=0xC6_33_64_FF+1;
		else if(nip==0xCB_00_71_00)nip=0xCB_00_71_FF+1;
		else if(nip==0xE0_00_00_00){

			nip--;
			return null;

		}

		return (nip>>>0x18 & 0xFF)+"."+
			   (nip>>>0x10 & 0xFF)+"."+
			   (nip>>>0x08 & 0xFF)+"."+
			   (nip>>>0x00 & 0xFF);

	}

	private static boolean bytesContain(byte[] source, int length, byte[] word){

	 fc:for(int s=0;s<length-word.length+1;s++){

			for(int w=0;w<word.length;w++)

				if(source[s+w]!=word[w])continue fc;

			return true;

		}

		return false;

	}

	private static synchronized void saveDIP(String ip) throws Exception{

		try(OutputStream os=new FileOutputStream(domain,true)){

			os.write((ip+'\n').getBytes());

		}

	}

	public static void main(String[] args) throws Exception{

		for(int i=0;i<threads;i++)

			new Thread(){

				public void run(){

					byte[] d=new byte[content];

					while(true)

						try{

							Thread.sleep(25);

							URLConnection uc=new URL(protocol+nextIP()).openConnection();
								uc.setConnectTimeout(timeout);
								uc.setReadTimeout(timeout);
								uc.setUseCaches(false);
								uc.setRequestProperty("Host",domain);

            				try(InputStream is=uc.getInputStream()){

                				if(bytesContain(d,is.read(d),word))saveDIP(uc.getURL().getHost());

            				}

						}catch(UnknownHostException uhe){

							return;

						}catch(Exception e){

							continue;

						}

				}

			}.start();

		while(true){

			int nipc=nip;

			System.out.println((nipc>>>0x18 & 0xFF)+"."+
			   	   			   (nipc>>>0x10 & 0xFF)+"."+
			  	   			   (nipc>>>0x08 & 0xFF)+"."+
				   			   (nipc>>>0x00 & 0xFF));

			Thread.sleep(5000);

			//System.gc();

		}

	}

}