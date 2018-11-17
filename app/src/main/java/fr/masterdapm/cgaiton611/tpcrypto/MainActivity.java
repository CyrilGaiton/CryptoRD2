package fr.masterdapm.cgaiton611.tpcrypto;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    EditText msg;
    EditText mdp;
//    TextView cle;
    TextView res;
    ClipboardManager myClipboard;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        msg = findViewById(R.id.msg);
        mdp = findViewById(R.id.mdp);
//        cle = findViewById(R.id.cle);
        res = findViewById(R.id.res);
        myClipboard = (ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
    }


    public void chiffrer(View v) {
        if( msg.getText().toString().length() == 0){
            Toast.makeText(this, "No message", Toast.LENGTH_SHORT).show();
        } else if (mdp.getText().toString().length() == 0){
            Toast.makeText(this, "No password", Toast.LENGTH_SHORT).show();
        } else {
            byte[] bytes = Chiffre(mdp.getText().toString().toCharArray(), msg.getText().toString().getBytes());
            String cryptoB64 = Base64.encodeToString(bytes, 0, bytes.length, Base64.NO_PADDING | Base64.NO_WRAP);
            res.setText(cryptoB64);
            msg.setText("");
            mdp.setText("");
        }
    }

    public void dechiffrer(View v){
        if( mdp.getText().toString().length() == 0){
            Toast.makeText(this, "No cryptogram", Toast.LENGTH_SHORT).show();
        } else if (msg.getText().toString().length() == 0) {
            Toast.makeText(this, "No password", Toast.LENGTH_SHORT).show();
        } else {
            byte[] cryptogram;
            try {
                cryptogram = Base64.decode(msg.getText().toString(), Base64.NO_PADDING | Base64.NO_WRAP);
            }
            catch (IllegalArgumentException e){
                Toast.makeText(this, "Bad cryptogram", Toast.LENGTH_SHORT).show();
                return;
            }
            if (cryptogram.length < (16 + 16)) {
                Toast.makeText(this, "Bad cryptogram", Toast.LENGTH_SHORT).show();
            } else {
                byte[] dechiffre = Dechiffre(mdp.getText().toString().toCharArray(), cryptogram);
                if(dechiffre == null){
                    Toast.makeText(this, "Bad cryptogram or password", Toast.LENGTH_SHORT).show();
                }
                else{
                    res.setText(new String(dechiffre, StandardCharsets.UTF_8));
                    msg.setText("");
                    mdp.setText("");
                }
            }
        }
    }


    public void copy(View v){
        ClipData myClip;
        myClip = ClipData.newPlainText("text", res.getText().toString());
        myClipboard.setPrimaryClip(myClip);
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
    }

    public void paste(View v){
        if (myClipboard.hasPrimaryClip()){
            ClipData myClip = myClipboard.getPrimaryClip();
            msg.setText(myClip.getItemAt(0).getText());
        }
        else{
            Toast.makeText(this, "Nothing to paste", Toast.LENGTH_SHORT).show();
        }

    }


    public SecretKey GenAESKeyFromPass(char[] password, byte[] sel, int iter, int taille) {
        SecretKey secretKeySpec = null;
        try {

            KeySpec keySpec = new PBEKeySpec(password, sel, iter, taille);
            SecretKeyFactory secretKeyFactory = null;
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
            secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return secretKeySpec;
    }


    public byte[] Chiffre(char[] password, byte[] plaintext) {
        ByteBuffer byteBuffer = null;
        try {

            SecureRandom secureRandom = new SecureRandom();
            byte[] sel = new byte[128/8];
            secureRandom.nextBytes(sel);

            SecretKey secretKey = GenAESKeyFromPass(mdp.getText().toString().toCharArray(), sel, 10000, 128);
//            cle.setText(Base64.encodeToString(secretKey.getEncoded(), 0, 128/8, Base64.NO_PADDING | Base64.NO_WRAP));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] chiffre = cipher.doFinal(msg.getText().toString().getBytes());

            Cipher cipherIV = Cipher.getInstance("AES/ECB/NoPadding");
            cipherIV.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] chiffreIV = cipherIV.doFinal(cipher.getIV());

            byteBuffer = ByteBuffer.allocate(256/8 + chiffre.length);
            byteBuffer.put(chiffreIV);
            byteBuffer.put(sel);
            byteBuffer.put(chiffre);


        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return byteBuffer.array();
    }

    public byte[] Dechiffre(char[] password, byte[] cryptogram){
        byte[] dechiffre = null;
        try {
            ByteBuffer byteBuffer = ByteBuffer.allocate(cryptogram.length);
            byteBuffer.put(cryptogram);
            byteBuffer.rewind();

            byte[] chiffreIV = new byte[128/8];
            byte[] sel = new byte[128/8];
            byte[] chiffre = new byte[cryptogram.length - 256/8];
            byteBuffer.get(chiffreIV, 0, 128/8);
            byteBuffer.get(sel, 0, 128/8);
            byteBuffer.get(chiffre, 0, cryptogram.length - 256/8);

            SecretKey secretKey = GenAESKeyFromPass(mdp.getText().toString().toCharArray(), sel, 10000, 128);
//            cle.setText(Base64.encodeToString(secretKey.getEncoded(), 0, 128/8, Base64.NO_PADDING | Base64.NO_WRAP));

            Cipher cipherIV = Cipher.getInstance("AES/ECB/NoPadding");
            cipherIV.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] dechiffreIV = cipherIV.doFinal(chiffreIV);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(dechiffreIV);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            dechiffre = cipher.doFinal(chiffre);



        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return dechiffre;
    }


}
