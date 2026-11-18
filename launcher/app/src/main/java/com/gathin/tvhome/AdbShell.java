package com.gathin.tvhome;

import android.content.Context;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

/**
 * A tiny ADB client that talks to this TV's own adbd on 127.0.0.1 (the "ADB over network" switch in Developer
 * options, port 5555), so a button in AURA can run shell commands the app itself may not run, such as
 * {@code pm disable-user}. It does only the classic handshake (CNXN, AUTH, OPEN shell:); no TLS pairing.
 * The first connection makes the TV ask once to allow this key; tick "always allow".
 */
final class AdbShell {
    private AdbShell() { }

    interface Result { void done(boolean ok, String text); }

    private static final int A_CNXN = 0x4e584e43;
    private static final int A_AUTH = 0x48545541;
    private static final int A_OPEN = 0x4e45504f;
    private static final int A_OKAY = 0x59414b4f;
    private static final int A_CLSE = 0x45534c43;
    private static final int A_WRTE = 0x45545257;
    private static final byte[] SHA1_PREFIX = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

    /** Runs the commands one after another on a worker thread and reports the output (or why it could not connect). */
    static void run(final Context ctx, final int port, final List<String> commands, final Result result) {
        final Context app = ctx.getApplicationContext();
        new Thread(() -> {
            StringBuilder out = new StringBuilder();
            try {
                for (String cmd : commands) {
                    String o = execute(app, port, cmd).trim();
                    out.append("$ ").append(cmd).append('\n');
                    if (!o.isEmpty()) out.append(o).append('\n');
                }
                result.done(true, out.toString().trim());
            } catch (ConnectException e) {
                result.done(false, "no-adb");
            } catch (SocketTimeoutException e) {
                result.done(false, "timeout");
            } catch (Exception e) {
                result.done(false, String.valueOf(e.getMessage()));
            }
        }, "aura-adb").start();
    }

    private static String execute(Context ctx, int port, String command) throws Exception {
        RSAPrivateKey key = loadKey(ctx);
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", port), 3000);
            s.setSoTimeout(10000);
            OutputStream o = s.getOutputStream();
            DataInputStream in = new DataInputStream(s.getInputStream());
            send(o, A_CNXN, 0x01000001, 4096, "host::aura\0".getBytes(StandardCharsets.UTF_8));
            Msg m = read(in);
            boolean signed = false;
            while (m.cmd == A_AUTH) {
                if (!signed) {
                    Signature sig = Signature.getInstance("NONEwithRSA");
                    sig.initSign(key);
                    sig.update(SHA1_PREFIX);
                    sig.update(m.data);
                    send(o, A_AUTH, 2, 0, sig.sign());
                    signed = true;
                } else {
                    byte[] pub = (Base64.encodeToString(adbPublicKey(key), Base64.NO_WRAP) + " aura@tv\0").getBytes(StandardCharsets.UTF_8);
                    send(o, A_AUTH, 3, 0, pub);
                    s.setSoTimeout(60000); // the TV asks the owner to allow this key
                }
                m = read(in);
            }
            if (m.cmd != A_CNXN) throw new IOException("adb: unexpected reply");
            s.setSoTimeout(15000);
            send(o, A_OPEN, 1, 0, ("shell:" + command + "\0").getBytes(StandardCharsets.UTF_8));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int remote = 0;
            while (true) {
                m = read(in);
                if (m.cmd == A_OKAY) { remote = m.a0; continue; }
                if (m.cmd == A_WRTE) {
                    out.write(m.data);
                    send(o, A_OKAY, 1, m.a0, null);
                    continue;
                }
                if (m.cmd == A_CLSE) break;
            }
            return out.toString("UTF-8");
        }
    }

    private static final class Msg { int cmd; int a0; int a1; byte[] data; }

    private static void send(OutputStream o, int cmd, int a0, int a1, byte[] data) throws IOException {
        int len = data == null ? 0 : data.length;
        int sum = 0;
        for (int i = 0; i < len; i++) sum += data[i] & 0xff;
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(cmd).putInt(a0).putInt(a1).putInt(len).putInt(sum).putInt(cmd ^ 0xffffffff);
        o.write(b.array());
        if (len > 0) o.write(data);
        o.flush();
    }

    private static Msg read(DataInputStream in) throws IOException {
        byte[] h = new byte[24];
        in.readFully(h);
        ByteBuffer b = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN);
        Msg m = new Msg();
        m.cmd = b.getInt();
        m.a0 = b.getInt();
        m.a1 = b.getInt();
        int len = b.getInt();
        if (len < 0 || len > (1 << 20)) throw new IOException("adb: bad length");
        m.data = new byte[len];
        in.readFully(m.data);
        return m;
    }

    private static RSAPrivateKey loadKey(Context ctx) throws Exception {
        File f = new File(ctx.getFilesDir(), "adb_key.pk8");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        if (f.exists()) {
            byte[] der = new byte[(int) f.length()];
            try (DataInputStream in = new DataInputStream(new FileInputStream(f))) { in.readFully(der); }
            return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        try (FileOutputStream out = new FileOutputStream(f)) { out.write(kp.getPrivate().getEncoded()); }
        return (RSAPrivateKey) kp.getPrivate();
    }

    /** The public key in the layout adbd reads: length in words, -1/n mod 2^32, n, R^2 mod n, exponent (all little-endian). */
    private static byte[] adbPublicKey(RSAPrivateKey key) {
        BigInteger n = key.getModulus();
        BigInteger two32 = BigInteger.ONE.shiftLeft(32);
        int n0inv = n.modInverse(two32).negate().mod(two32).intValue();
        BigInteger rr = BigInteger.ONE.shiftLeft(4096).mod(n);
        ByteBuffer b = ByteBuffer.allocate(4 + 4 + 256 + 256 + 4).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(64).putInt(n0inv);
        for (int i = 0; i < 64; i++) b.putInt(n.shiftRight(32 * i).and(BigInteger.valueOf(0xffffffffL)).intValue());
        for (int i = 0; i < 64; i++) b.putInt(rr.shiftRight(32 * i).and(BigInteger.valueOf(0xffffffffL)).intValue());
        b.putInt(65537);
        return b.array();
    }
}
