package com.sparrowwallet.sparrow.gui;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.bip47.PaymentCode;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.ScriptType;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.VBox;

import java.security.SignatureException;
import java.util.Locale;

public class Bip47MessageVerifierController {
    private static final String RELEASE_SIGNING_PAYMENT_CODE = "PM8TJM51x2mDd85CzEgVc2y7vdyB3eBj93JVjVtCt6PZtmfzhFzYPMXYBXh28zthWhVKGjVQZPT1MKxGxEtfenLYEkuc5GhoWtMzQCF8c8mrckYFM7r1";

    @FXML private TextArea paymentCodeArea;
    @FXML private TextArea signedBlockArea;
    @FXML private TextArea messageArea;
    @FXML private TextArea signatureArea;
    @FXML private VBox resultBox;
    @FXML private Label resultTitleLabel;
    @FXML private Label notificationAddressLabel;
    @FXML private Label signerAddressLabel;

    @FXML
    private void onUseReleaseCode() {
        paymentCodeArea.setText(RELEASE_SIGNING_PAYMENT_CODE);
    }

    @FXML
    private void onParseSignedBlock() {
        try {
            SignedMessageBlock parsed = parseSignedMessageBlock(signedBlockArea.getText());
            messageArea.setText(parsed.message());
            signatureArea.setText(parsed.signature());
            showInfo("Signed message block parsed", null, null);
        } catch(Exception e) {
            showError(e.getMessage());
        }
    }

    @FXML
    private void onVerify() {
        try {
            String paymentCodeText = paymentCodeArea.getText() == null ? "" : paymentCodeArea.getText().trim();
            if(paymentCodeText.isEmpty()) {
                throw new IllegalArgumentException("BIP47 payment code is required");
            }

            String message = messageArea.getText();
            String signature = signatureArea.getText() == null ? "" : signatureArea.getText().trim();
            if((message == null || message.isEmpty()) && signedBlockArea.getText() != null && !signedBlockArea.getText().isBlank()) {
                SignedMessageBlock parsed = parseSignedMessageBlock(signedBlockArea.getText());
                message = parsed.message();
                signature = parsed.signature();
                messageArea.setText(message);
                signatureArea.setText(signature);
            }

            if(message == null || message.isEmpty()) {
                throw new IllegalArgumentException("Message is required");
            }
            if(signature.isEmpty()) {
                throw new IllegalArgumentException("Base64 signature is required");
            }

            PaymentCode paymentCode = new PaymentCode(paymentCodeText);
            Address notificationAddress = paymentCode.getNotificationAddress();
            ECKey recoveredKey = ECKey.signedMessageToKey(message, signature, false);
            Address recoveredAddress = ScriptType.P2PKH.getAddress(recoveredKey);

            if(notificationAddress.equals(recoveredAddress)) {
                showSuccess(notificationAddress.toString(), recoveredAddress.toString());
            } else {
                showInvalid(notificationAddress.toString(), recoveredAddress.toString());
            }
        } catch(SignatureException e) {
            showError("Signature could not be verified: " + e.getMessage());
        } catch(Exception e) {
            showError(e.getMessage());
        }
    }

    private void showSuccess(String notificationAddress, String signerAddress) {
        resultBox.getStyleClass().removeAll("verifier-result-error", "verifier-result-info");
        if(!resultBox.getStyleClass().contains("verifier-result-success")) {
            resultBox.getStyleClass().add("verifier-result-success");
        }
        showInfo("Signature verified", notificationAddress, signerAddress);
    }

    private void showInvalid(String notificationAddress, String signerAddress) {
        resultBox.getStyleClass().removeAll("verifier-result-success", "verifier-result-info");
        if(!resultBox.getStyleClass().contains("verifier-result-error")) {
            resultBox.getStyleClass().add("verifier-result-error");
        }
        showInfo("Signature does not match this payment code", notificationAddress, signerAddress);
    }

    private void showError(String error) {
        resultBox.getStyleClass().removeAll("verifier-result-success", "verifier-result-info");
        if(!resultBox.getStyleClass().contains("verifier-result-error")) {
            resultBox.getStyleClass().add("verifier-result-error");
        }
        showInfo("Verification error: " + error, null, null);
    }

    private void showInfo(String title, String notificationAddress, String signerAddress) {
        resultTitleLabel.setText(title);
        notificationAddressLabel.setText(notificationAddress == null ? "" : "Notification address: " + notificationAddress);
        signerAddressLabel.setText(signerAddress == null ? "" : "Recovered signer address: " + signerAddress);
        resultBox.setVisible(true);
        resultBox.setManaged(true);
    }

    private static SignedMessageBlock parseSignedMessageBlock(String block) {
        if(block == null || block.isBlank()) {
            throw new IllegalArgumentException("Signed message block is empty");
        }

        String upper = block.toUpperCase(Locale.ROOT);
        String beginMessage = "-----BEGIN BITCOIN SIGNED MESSAGE-----";
        String beginSignature = "-----BEGIN BITCOIN SIGNATURE-----";
        String endSignature = "-----END BITCOIN SIGNATURE-----";

        int messageStart = upper.indexOf(beginMessage);
        int signatureStart = upper.indexOf(beginSignature);
        if(messageStart < 0 || signatureStart < 0 || signatureStart <= messageStart) {
            throw new IllegalArgumentException("Signed block must include BEGIN BITCOIN SIGNED MESSAGE and BEGIN BITCOIN SIGNATURE markers");
        }

        int signatureEnd = upper.indexOf(endSignature, signatureStart + beginSignature.length());
        if(signatureEnd < 0) {
            throw new IllegalArgumentException("Signed block is missing END BITCOIN SIGNATURE marker");
        }

        String message = stripOuterLineBreaks(block.substring(messageStart + beginMessage.length(), signatureStart));
        String signatureSection = block.substring(signatureStart + beginSignature.length(), signatureEnd);
        String signature = "";
        for(String line : signatureSection.split("\\R")) {
            String trimmed = line.trim();
            if(trimmed.isEmpty() || trimmed.toLowerCase(Locale.ROOT).startsWith("version:") || trimmed.toLowerCase(Locale.ROOT).startsWith("address:")) {
                continue;
            }
            signature = trimmed;
        }

        if(message.isEmpty()) {
            throw new IllegalArgumentException("Could not extract message from signed block");
        }
        if(signature.isEmpty()) {
            throw new IllegalArgumentException("Could not extract signature from signed block");
        }

        return new SignedMessageBlock(message, signature);
    }

    private static String stripOuterLineBreaks(String value) {
        return value.replaceFirst("^\\R+", "").replaceFirst("\\R+$", "");
    }

    private record SignedMessageBlock(String message, String signature) { }
}
