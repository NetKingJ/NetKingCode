package Java_GUI_Program;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

public class Hashing_Program extends JFrame {
	private static final long serialVersionUID = 1L;
	
	// ###########################################
	// ############## 작업 생성 영역 ###############
	// ###########################################
		
	JLabel input_lb = new JLabel("Input"); // 입력 라벨 생성
	JTextArea input_ta = new JTextArea(); // 입력 텍스트 영역 생성
	JScrollPane input_sp = new JScrollPane(input_ta); // 입력 스크롤 생성
	
	JLabel output_lb = new JLabel("Ouput"); // 출력 라벨 생성
	JTextArea output_ta = new JTextArea(); // 출력 텍스트 영역 생성
	JScrollPane output_sp = new JScrollPane(output_ta); // 출력 스크롤 생성
	
	JButton base64_encode_btn = new JButton("Base64 Encode"); // Base64 인코딩 버튼 생성
	JButton base64_decode_btn = new JButton("Base64 Decode"); // Base64 디코딩 버튼 생성
	JButton url_encode_btn = new JButton("URL Encode"); // URL 인코딩 버튼 생성
	JButton url_decode_btn = new JButton("URL Decode"); // URL 디코딩 버튼 생성
	JButton hex_encode_btn = new JButton("HEX Encode"); // HEX 인코딩 버튼 생성
	JButton hex_decode_btn = new JButton("HEX Decode"); // HEX 디코딩 버튼 생성
	JButton md5_btn = new JButton("MD5"); // MD5 버튼 생성
	JButton sha1_btn = new JButton("SHA-1"); // SHA-1 버튼 생성
	JButton sha256_btn = new JButton("SHA-256"); // SHA-256 버튼 생성
	JButton reverse_btn = new JButton("Reverse"); // Reverse 버튼 생성 
	JButton factorization_btn = new JButton("Factorization"); // ASE 인코딩 버튼 생성

	public Hashing_Program() {
		JFrame f = new JFrame("Hashing Program ver.200610"); // 프레임 생성
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // 종료 활성화
		Container p = getContentPane(); // 패널 생성
		p.setLayout(null);
		
		// ###########################################
		// ############## 필드 작업 영역 ###############
		// ###########################################
		
		// 입력
		input_lb.setBounds(0, 0, 600, 30);
		input_lb.setOpaque(true);
		input_lb.setBackground(Color.white);
		input_lb.setFont(input_lb.getFont().deriveFont(20f));
		p.add(input_lb);
		input_ta.setLineWrap(true); // 가로 폭 유지 (스크롤 내려가기만 하도록)
		input_ta.setFont(new Font("Gothic", Font.BOLD, 15)); // 출력 폰트
		input_sp.setBounds(0, 30, 600, 550);
		p.add(input_sp);
		
		// 출력
		output_lb.setBounds(600, 0, 600, 30);
		output_lb.setOpaque(true);
		output_lb.setBackground(Color.white);
		output_lb.setFont(input_lb.getFont().deriveFont(20f));
		p.add(output_lb);
		input_ta.setLineWrap(true); // 가로 폭 유지 (스크롤 내려가기만 하도록)
		output_ta.setFont(new Font("Gothic", Font.BOLD, 15)); // 출력 폰트
		output_sp.setBounds(600, 30, 600, 550);
		p.add(output_sp);
		
		// ###########################################
		// ############## 인코딩 버튼 영역 ##############
		// ###########################################
		
		// Base64
		base64_encode_btn.addActionListener(new ButtonListener());
		base64_encode_btn.setBounds(0, 580, 200, 28);
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
		// SHA-1
		sha1_btn.addActionListener(new ButtonListener());
		sha1_btn.setBounds(600, 580, 200, 28);
		p.add(sha1_btn);
		// SHA-256
		sha256_btn.addActionListener(new ButtonListener());
		sha256_btn.setBounds(600, 609, 200, 28);
		p.add(sha256_btn);
		// MD5
		md5_btn.addActionListener(new ButtonListener());
		md5_btn.setBounds(800, 580, 200, 28);
		p.add(md5_btn);
		// Reverse
		reverse_btn.addActionListener(new ButtonListener());
		reverse_btn.setBounds(800, 609, 200, 28);
		p.add(reverse_btn);
		// Factorization
		factorization_btn.addActionListener(new ButtonListener());
		factorization_btn.setBounds(1000, 580, 200, 28);
		p.add(factorization_btn);
		
		f.add(p); // 프레임에 패널 주입
		f.setSize(1215,675);
		f.setVisible(true); // 생성
	}
	
	// ###########################################
	// ############## 인코딩 작업 영역 ##############
	// ###########################################
	
	class ButtonListener implements ActionListener { 
		public void actionPerformed(ActionEvent e) {
			String input_value = input_ta.getText();
			
			// base64_encode_btn
			if(e.getSource().equals(base64_encode_btn)) {
				byte[] targetBytes = input_value.getBytes();
				Encoder encoder = Base64.getEncoder();
				byte[] encode_value = encoder.encode(targetBytes);
				output_ta.setText(new String(encode_value));
			
			// base64_decode_btn
			} else if(e.getSource().equals(base64_decode_btn)) {
				byte[] targetBytes = input_value.getBytes();
				Decoder decoder = Base64.getDecoder();
				byte[] decode_value = decoder.decode(targetBytes);
				output_ta.setText(new String(decode_value));
			
			// url_encode_btn
			} else if(e.getSource().equals(url_encode_btn)) {
				String encode_value = null;
				try {
					encode_value = URLEncoder.encode(input_value, "UTF-8");
				} catch (UnsupportedEncodingException e1) {
					e1.printStackTrace();
				}
				output_ta.setText(new String(encode_value));
				
			// url_decode_btn
			} else if(e.getSource().equals(url_decode_btn)) {
				String decode_value = null;
				try {
					decode_value = URLDecoder.decode(input_value, "UTF-8");
				} catch (UnsupportedEncodingException e1) {
					e1.printStackTrace();
				}
				output_ta.setText(new String(decode_value));
				
			// hex_encode_btn
			} else if(e.getSource().equals(hex_encode_btn)) {
				String encode_value = "";
				for (int i = 0; i < input_value.length(); i++) {
					encode_value += String.format("%02X", (int) input_value.charAt(i));
				}
				output_ta.setText(new String(encode_value));
				
			// hex_decode_btn
			} else if(e.getSource().equals(hex_decode_btn)) {
				final int RADIX = 16;
				String hexStr = input_value;
				String decode_value = new String((new BigInteger(hexStr, RADIX)).toByteArray());
				output_ta.setText(new String(decode_value));
			
			// MD5
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
				
			// SHA-1
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
				
			// SHA-256
			} else if(e.getSource().equals(sha256_btn)) {
				String encode_value = ""; 
				try{
					MessageDigest sh = MessageDigest.getInstance("SHA-256"); 
					sh.update(input_value.getBytes()); 
					byte byteData[] = sh.digest();
					StringBuffer sb = new StringBuffer(); 
					for(int i = 0 ; i < byteData.length ; i++){
						sb.append(Integer.toString((byteData[i]&0xff) + 0x100, 16).substring(1));
					}
					encode_value = sb.toString();
				}catch(NoSuchAlgorithmException e_sha256){
					e_sha256.printStackTrace(); 
					encode_value = null; 
				}
				output_ta.setText(new String(encode_value));

			// reverse
			} else if(e.getSource().equals(reverse_btn)) {
				String encode_value = new StringBuilder(input_value).reverse().toString();
				output_ta.setText(new String(encode_value));
				
			// factorization_btn	
			} else if(e.getSource().equals(factorization_btn)) {
		        long n = Long.parseLong(input_value);
		        output_ta.setText("");
		        while (n > 1) {
		            for (long i = 2; i <= n; i++) {
		                if (n % i == 0) {
		                	String encode_value = String.valueOf(i);
		                    output_ta.setText(new String(encode_value+"\n"+output_ta.getText()));
		                    n = n / i;
		                    break;
		                }
		            }
		        }
			}
		}
	}

	// #############################################
	// ################# main 영역 #################
	// #############################################
	
	public static void main(String[] args) {
		new Hashing_Program();
	}
}
