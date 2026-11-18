package com.gathin.tvhome;

import android.content.Intent;
import android.speech.RecognitionService;
import android.speech.SpeechRecognizer;

/**
 * Not a speech recogniser: Android 11 refuses a voice-interaction service that names no recognition service, so AURA's
 * assistant entry points here. It is never offered as a recogniser (no RecognitionService intent filter) and answers
 * every request with an error. AURA's voice search uses the TV's own recogniser.
 */
public class AuraRecognitionService extends RecognitionService {
    @Override
    protected void onStartListening(Intent recognizerIntent, Callback listener) {
        try { listener.error(SpeechRecognizer.ERROR_CLIENT); } catch (Exception ignored) { }
    }

    @Override
    protected void onCancel(Callback listener) {
    }

    @Override
    protected void onStopListening(Callback listener) {
    }
}
