package org.example;

import io.javalin.Javalin;
import io.javalin.plugin.bundled.CorsPluginConfig;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Objects;

public class Main {
    public static void main(String[] args) {
        Javalin app = Javalin.create(config -> {
            config.plugins.enableCors(cors -> {
                cors.add(CorsPluginConfig::anyHost);
            });
        }).start(8080);

        app.post("/encrypt", ctx -> {
            String key = ctx.formParam("key");
            String operation = ctx.formParam("operation");
            String mode = ctx.formParam("mode");

            var uploadedFile = Objects.requireNonNull(ctx.uploadedFile("image"));
            byte[] imageBytes;
            try (InputStream inputStream = uploadedFile.content()) {
                imageBytes = inputStream.readAllBytes();
            }

            assert key != null;

            byte[] processedData;
            String outputFilePath;
            if ("encrypt".equalsIgnoreCase(operation)) {
                processedData = encrypt(imageBytes, key, mode);
                outputFilePath = "encrypted_image.bmp";
            } else {
                processedData = decrypt(imageBytes, key, mode);
                outputFilePath = "decrypted_image.bmp";
            }

            // Save the processed data to a local file
            try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
                fos.write(processedData);
            }

            // Send the processed data back to the client
            ctx.result(processedData).contentType("application/octet-stream");
        });
    }

    public static byte[] encrypt(byte[] data, String key, String mode) throws Exception {
        Cipher cipher;
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        if ("ECB".equalsIgnoreCase(mode)) {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } else if ("CBC".equalsIgnoreCase(mode)) {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(iv);  // Prepend IV to the output
            outputStream.write(cipher.doFinal(data));
            return outputStream.toByteArray();
        } else {
            throw new IllegalArgumentException("Unsupported mode: " + mode);
        }
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String key, String mode) throws Exception {
        Cipher cipher;
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        if ("ECB".equalsIgnoreCase(mode)) {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } else if ("CBC".equalsIgnoreCase(mode)) {
            byte[] iv = new byte[16];
            System.arraycopy(data, 0, iv, 0, iv.length);
            byte[] encryptedData = new byte[data.length - iv.length];
            System.arraycopy(data, iv.length, encryptedData, 0, encryptedData.length);
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
            return cipher.doFinal(encryptedData);
        } else {
            throw new IllegalArgumentException("Unsupported mode: " + mode);
        }
    }
//    private static void publishToJMSTopic(byte[] data, String key, String operation, String mode) throws Exception {
//        ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory("tcp://localhost:61616");
//        Connection connection = connectionFactory.createConnection();
//        connection.start();
//
//        Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
//        Topic topic = session.createTopic("ImageProcessingTopic");
//
//        MessageProducer producer = session.createProducer(topic);
//        BytesMessage message = session.createBytesMessage();
//        message.writeBytes(data);
//        message.setStringProperty("key", key);
//        message.setStringProperty("operation", operation);
//        message.setStringProperty("mode", mode);
//
//        producer.send(message);
//        connection.close();
//    }
}