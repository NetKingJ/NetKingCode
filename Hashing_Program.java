package Java_GUI_Program;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

public class Hashing_Program extends JFrame implements KeyListener {
	private static final long serialVersionUID = 1L;
	
	// ###########################################
	// ############## �۾� ���� ���� ###############
	// ###########################################
		
	JLabel input_lb = new JLabel("Input"); // �Է� �� ����
	JTextArea input_ta = new JTextArea(); // �Է� �ؽ�Ʈ ���� ����
	JScrollPane input_sp = new JScrollPane(input_ta); // �Է� ��ũ�� ����
	JLabel input_length_lb = new JLabel("(length: 0)"); // �Է� ���� �� ����
	
	JLabel output_lb = new JLabel("Ouput"); // ��� �� ����
	JTextArea output_ta = new JTextArea(); // ��� �ؽ�Ʈ ���� ����
	JScrollPane output_sp = new JScrollPane(output_ta); // ��� ��ũ�� ����
	JLabel output_length_lb = new JLabel("(length: 0)"); // ��� ���� �� ����
	
	JButton base64_encode_btn = new JButton("Base64 Encode"); // Base64 ���ڵ� ��ư ����
	JButton base64_decode_btn = new JButton("Base64 Decode"); // Base64 ���ڵ� ��ư ����
	JButton url_encode_btn = new JButton("URL Encode"); // URL ���ڵ� ��ư ����
	JButton url_decode_btn = new JButton("URL Decode"); // URL ���ڵ� ��ư ����
	JButton hex_encode_btn = new JButton("HEX Encode"); // HEX ���ڵ� ��ư ����
	JButton hex_decode_btn = new JButton("HEX Decode"); // HEX ���ڵ� ��ư ����
	JButton sha1_btn = new JButton("SHA-1"); // SHA-1 ��ư ����
	JButton sha256_btn = new JButton("SHA-256"); // SHA-256 �ؽ� ��ư ����
	// AES-256�� �ڹ� ��å���� ���̺귯��(US_export_policy.jar, local_policy.jar) �߰��ϼž� ������ ����
	JButton aes256_encrypt_btn = new JButton("AES-256 Encrypt"); // AES-256 ��ȣȭ ����
	JButton aes256_decrypt_btn = new JButton("AES-256 Decrypt"); // AES-256 ��ȣȭ ����
	JButton md5_btn = new JButton("MD5"); // MD5 ��ư ����
	JButton factorization_btn = new JButton("Factorization"); // Factorization ���ڵ� ��ư ����

	public Hashing_Program() {
		JFrame f = new JFrame("Hashing Program ver.200612"); // ������ ����
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // ���� Ȱ��ȭ
		Container p = getContentPane(); // �г� ����
		p.setLayout(null);
		
		// ###########################################
		// ############## �۾� ���� ###################
		// ###########################################
		
		// �Է�
		input_length_lb.setBounds(55, 0, 400, 30);
		input_length_lb.setOpaque(false);
		input_length_lb.setFont(input_length_lb.getFont().deriveFont(20f));
		p.add(input_length_lb);
		input_lb.setBounds(0, 0, 600, 30);
		input_lb.setOpaque(true);
		input_lb.setBackground(Color.white);
		input_lb.setFont(input_lb.getFont().deriveFont(20f));
		p.add(input_lb);
		input_ta.setLineWrap(true); // ���� �� ���� (��ũ�� �������⸸ �ϵ���)
		input_ta.setFont(new Font("Gothic", Font.BOLD, 15)); // ��� ��Ʈ
		input_ta.addKeyListener(this); // Ű���� ������
		input_sp.setBounds(0, 30, 600, 550);
		p.add(input_sp);

		// ���
		output_length_lb.setBounds(665, 0, 400, 30);
		output_length_lb.setOpaque(false);
		output_length_lb.setFont(output_length_lb.getFont().deriveFont(20f));
		p.add(output_length_lb);
		output_lb.setBounds(600, 0, 600, 30);
		output_lb.setOpaque(true);
		output_lb.setBackground(Color.white);
		output_lb.setFont(input_lb.getFont().deriveFont(20f));
		p.add(output_lb);
		output_ta.setLineWrap(true); // ���� �� ���� (��ũ�� �������⸸ �ϵ���)
		output_ta.setFont(new Font("Gothic", Font.BOLD, 15)); // ��� ��Ʈ
		output_sp.setBounds(600, 30, 600, 550);
		p.add(output_sp);
		
		// ###########################################
		// ############## �ؽ� ��ư ���� ###############
		// ###########################################
		
		// Base64
		base64_encode_btn.addActionListener(new ButtonListener());
		base64_encode_btn.setBounds(0, 580, 200, 28);
		base64_encode_btn.addKeyListener(this);
		p.add(base64_encode_btn);
		base64_decode_btn.addActionListener(new ButtonListener());
		base64_decode_btn.setBounds(0, 609, 200, 28);
		p.add(base64_decode_btn);
		// URL
		url_encode_btn.addActionListener(new ButtonListener());
		url_encode_btn.setBounds(200, 580, 200, 28);
		p.add(url_encode_btn);
		url_decode_btn.addActionListener(new ButtonListener());
		url_decode_btn.setBounds(200, 609, 200, 28);
		p.add(url_decode_btn);
		// HEX
		hex_encode_btn.addActionListener(new ButtonListener());
		hex_encode_btn.setBounds(400, 580, 200, 28);
		p.add(hex_encode_btn);
		hex_decode_btn.addActionListener(new ButtonListener());
		hex_decode_btn.setBounds(400, 609, 200, 28);
		p.add(hex_decode_btn);
		// aes256_encryption_btn
		aes256_encrypt_btn.addActionListener(new ButtonListener());
		aes256_encrypt_btn.setBounds(600, 580, 200, 28);
		p.add(aes256_encrypt_btn);
		// aes256_decryption_btn
		aes256_decrypt_btn.addActionListener(new ButtonListener());
		aes256_decrypt_btn.setBounds(600, 609, 200, 28);
		p.add(aes256_decrypt_btn);
		// SHA-1
		sha1_btn.addActionListener(new ButtonListener());
		sha1_btn.setBounds(800, 580, 200, 28);
		p.add(sha1_btn);
		// SHA-256
		sha256_btn.addActionListener(new ButtonListener());
		sha256_btn.setBounds(800, 609, 200, 28);
		p.add(sha256_btn);
		// MD5
		md5_btn.addActionListener(new ButtonListener());
		md5_btn.setBounds(1000, 580, 200, 28);
		p.add(md5_btn);
		// Factorization
		factorization_btn.addActionListener(new ButtonListener());
		factorization_btn.setBounds(1000, 609, 200, 28);
		p.add(factorization_btn);
		
		f.add(p); // �����ӿ� �г� ����
		f.setSize(1215,675); // 16��9 ����
		f.setVisible(true); // ����
	}
	
	// Ű���� �Է¸��� �ؽ�Ʈ �ʵ� ���� ����
	public void keyReleased(KeyEvent e) {
		input_length_lb.setText(new String("(length: "+Integer.toString(input_ta.getText().length())+")"));
	}
	
	// ###########################################
	// ############## �ؽ� �۾� ���� ###############
	// ###########################################
	
	class ButtonListener implements ActionListener { 
		public void actionPerformed(ActionEvent e) {
			String input_value = input_ta.getText();
			
			// base64_encode_btn
			if(e.getSource().equals(base64_encode_btn)) {		
				byte[] targetBytes = input_value.getBytes();
				Encoder encoder = Base64.getEncoder();
				byte[] base64_encode_value = encoder.encode(targetBytes);
				output_ta.setText(new String(base64_encode_value));
			
			// base64_decode_btn
			} else if(e.getSource().equals(base64_decode_btn)) {
				byte[] targetBytes = input_value.getBytes();
				Decoder decoder = Base64.getDecoder();
				byte[] base64_decode_value = decoder.decode(targetBytes);
				output_ta.setText(new String(base64_decode_value));
			
			// url_encode_btn
			} else if(e.getSource().equals(url_encode_btn)) {
				String url_encode_value = null;
				try {
					url_encode_value = URLEncoder.encode(input_value, "UTF-8");
				} catch (UnsupportedEncodingException e_url) {
					e_url.printStackTrace();
				}
				output_ta.setText(new String(url_encode_value));
				
			// url_decode_btn
			} else if(e.getSource().equals(url_decode_btn)) {
				String url_decode_value = null;
				try {
					url_decode_value = URLDecoder.decode(input_value, "UTF-8");
				} catch (UnsupportedEncodingException e_url) {
					e_url.printStackTrace();
				}
				output_ta.setText(new String(url_decode_value));
				
			// hex_encode_btn
			} else if(e.getSource().equals(hex_encode_btn)) {
				String hex_encode_value = "";
				for (int i = 0; i < input_value.length(); i++) {
					hex_encode_value += String.format("%02X", (int) input_value.charAt(i));
				}
				output_ta.setText(new String(hex_encode_value));
				
			// hex_decode_btn
			} else if(e.getSource().equals(hex_decode_btn)) {
				final int RADIX = 16;
				String hex_decode_value = new String((new BigInteger(input_value, RADIX)).toByteArray());
				output_ta.setText(new String(hex_decode_value));
			
			// md5_btn
			} else if(e.getSource().equals(md5_btn)) {
				String encode_value = ""; 
				try{
					MessageDigest md = MessageDigest.getInstance("MD5"); 
					md.update(input_value.getBytes()); 
					byte byteData[] = md.digest();
					StringBuffer sb = new StringBuffer(); 
					for(int i = 0 ; i < byteData.length ; i++){
						sb.append(Integer.toString((byteData[i]&0xff) + 0x100, 16).substring(1));
					}
					encode_value = sb.toString();
				}catch(NoSuchAlgorithmException e_md5){
					e_md5.printStackTrace(); 
					encode_value = null;
				}
				output_ta.setText(new String(encode_value));
				
			// sha1_btn
			} else if(e.getSource().equals(sha1_btn)) {
				try {
		            MessageDigest md = MessageDigest.getInstance("SHA-1"); 
		            byte[] messageDigest = md.digest(input_value.getBytes());
		            BigInteger no = new BigInteger(1, messageDigest);
		            String encode_value = no.toString(16);
		            while (encode_value.length() < 32) { 
		            	encode_value = "0" + encode_value; 
		            }
		            output_ta.setText(new String(encode_value));
		        }
		        catch (NoSuchAlgorithmException e_sha1) { 
		            throw new RuntimeException(e_sha1); 
		        }
				
			// sha256_btn
			} else if(e.getSource().equals(sha256_btn)) {
				String sha256_hash_value = ""; 
				try{
					MessageDigest sh = MessageDigest.getInstance("SHA-256"); 
					sh.update(input_value.getBytes()); 
					byte byteData[] = sh.digest();
					StringBuffer sb = new StringBuffer(); 
					for(int i = 0 ; i < byteData.length ; i++){
						sb.append(Integer.toString((byteData[i]&0xff) + 0x100, 16).substring(1));
					}
					sha256_hash_value = sb.toString();
				}catch(NoSuchAlgorithmException e_sha256){
					e_sha256.printStackTrace(); 
					sha256_hash_value = null; 
				}
				output_ta.setText(new String(sha256_hash_value));
				
			// factorization_btn	
			} else if(e.getSource().equals(factorization_btn)) {
				output_ta.setText("");
		        long n = Long.parseLong(input_value);
		        while (n > 1) {
		            for (long i = 2; i <= n; i++) {
		                if (n % i == 0) {
		                	String factorization_hash_value = String.valueOf(i);
		                    output_ta.setText(new String(factorization_hash_value + "\n" + output_ta.getText()));
		                    n = n / i;
		                    break;
		                }
		            }
		        }
		     
		    // aes256_encrypt_btn
			} else if(e.getSource().equals(aes256_encrypt_btn)) {
				 String encryptedString = aes256_encrypt(input_value, secretKey);
				 output_ta.setText(new String(encryptedString));
				 
			// aes256_decrypt_btn
			} else if(e.getSource().equals(aes256_decrypt_btn)) {
				String decryptedString = aes256_decrypt(input_value, secretKey);
				output_ta.setText(new String(decryptedString));
			}
			
			output_length_lb.setText(new String("(length: "+Integer.toString(output_ta.getText().length())+")")); // ��ư �������� ���� ��� ���� ����
		}
	}
	
	// #######################################
	// ############## �Լ� ���� ###############
	// #######################################
	
	// AES-256
	private static String secretKey = "boooooooooom!!!!";
    private static String salt = "ssshhhhhhhhhhh!!!!";
    public static String aes256_encrypt(String strToEncrypt, String secret) 
    {
        try
        {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
             
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
             
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } 
        catch (Exception e_aes256_encrypt) 
        {
            System.out.println("Error while encrypting: " + e_aes256_encrypt.toString());
        }
        return null;
    }

    public static String aes256_decrypt(String strToDecrypt, String secret) {
        try
        {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
             
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
             
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } 
        catch (Exception aes256_decrypt) {
            System.out.println("Error while decrypting: " + aes256_decrypt.toString());
        }
        return null;
    }
	
	// #############################################
	// ################# main ���� #################
	// #############################################
	
	public static void main(String[] args) {
		new Hashing_Program();
	}

	@Override
	public void keyTyped(KeyEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void keyPressed(KeyEvent e) {
		// TODO Auto-generated method stub
		
	}
}
