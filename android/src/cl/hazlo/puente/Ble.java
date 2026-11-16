package cl.hazlo.puente;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertisingSet;
import android.bluetooth.le.AdvertisingSetCallback;
import android.bluetooth.le.AdvertisingSetParameters;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.SystemClock;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Señal Bluetooth para el Mac:
 *  - Anuncio con un identificador que cambia cada 15 min (HMAC con una llave que solo conocen el Mac y el celular),
 *    para medir la distancia sin que terceros puedan rastrear el celular.
 *  - Servicio GATT que recibe comandos firmados del Mac (prender/apagar hotspot), aun sin Wi‑Fi en común.
 */
final class Ble {
    static final UUID SERVICE = UUID.fromString("6b1f3a52-9d2e-4c47-8a51-50756e746531");
    static final UUID COMMAND = UUID.fromString("6b1f3a52-9d2e-4c47-8a51-50756e746532");
    /** Puerto (PSM) del canal L2CAP: el mismo enlace cifrado que por Wi‑Fi, pero por Bluetooth. */
    static final UUID TUNNEL = UUID.fromString("6b1f3a52-9d2e-4c47-8a51-50756e746533");
    static final int MANUFACTURER = 0xFFFF;
    static final long WINDOW_S = 900;

    private final Context ctx;
    private final Consumer<JSONObject> report;
    private BluetoothLeAdvertiser advertiser;
    private AdvertisingSet set;
    private BluetoothGattServer gatt;
    private byte[] key;
    private long lastCmdTs;
    private final java.util.Map<String, byte[]> prepared = new java.util.HashMap<>();
    private boolean receiverOn;
    private android.bluetooth.BluetoothServerSocket l2cap;

    Ble(Context ctx, Consumer<JSONObject> report) { this.ctx = ctx; this.report = report; }

    private SharedPreferences prefs() { return ctx.getSharedPreferences("link", Context.MODE_PRIVATE); }

    synchronized void start() {
        String hex = prefs().getString("bleKey", null);
        if (hex == null) return;
        key = hexToBytes(hex);
        if (!receiverOn) {
            ctx.registerReceiver(btState, new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED), Context.RECEIVER_EXPORTED);
            receiverOn = true;
        }
        BluetoothAdapter a = ctx.getSystemService(BluetoothManager.class).getAdapter();
        if (a == null || !a.isEnabled()) { state(false); return; }
        try {
            startGatt();
            startTunnel(a);
            startAdvertising(a);
            scheduleRotation();
        } catch (SecurityException e) {
            state(false);
        }
    }

    synchronized void stop() {
        try {
            if (set != null && advertiser != null) advertiser.stopAdvertisingSet(advCallback);
            if (gatt != null) gatt.close();
            if (l2cap != null) l2cap.close();
        } catch (Exception ignored) {}
        set = null; gatt = null; advertiser = null; l2cap = null;
    }

    // ---------- anuncio ----------

    private final AdvertisingSetCallback advCallback = new AdvertisingSetCallback() {
        @Override public void onAdvertisingSetStarted(AdvertisingSet s, int txPower, int status) {
            set = s;
            state(status == ADVERTISE_SUCCESS);
        }
        @Override public void onAdvertisingSetStopped(AdvertisingSet s) { set = null; }
    };

    private void startAdvertising(BluetoothAdapter a) {
        if (set != null) { rotate(); return; }
        advertiser = a.getBluetoothLeAdvertiser();
        if (advertiser == null) { state(false); return; }
        AdvertisingSetParameters p = new AdvertisingSetParameters.Builder()
                .setLegacyMode(true).setConnectable(true).setScannable(true)
                .setInterval(AdvertisingSetParameters.INTERVAL_MEDIUM)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_MEDIUM)
                .build();
        advertiser.startAdvertisingSet(p, data(), null, null, null, advCallback);
    }

    private AdvertiseData data() {
        return new AdvertiseData.Builder().setIncludeDeviceName(false).setIncludeTxPowerLevel(false)
                .addManufacturerData(MANUFACTURER, payload()).build();
    }

    /** 'P', versión 1 y 8 bytes de HMAC(llave, 'P' + ventana de 15 min). */
    private byte[] payload() {
        long w = System.currentTimeMillis() / 1000 / WINDOW_S;
        byte[] h = hmac(ByteBuffer.allocate(9).put((byte) 'P').putLong(w).array());
        byte[] out = new byte[10];
        out[0] = 'P'; out[1] = 1;
        System.arraycopy(h, 0, out, 2, 8);
        return out;
    }

    synchronized void rotate() {
        try { if (set != null) set.setAdvertisingData(data()); } catch (SecurityException ignored) {}
        scheduleRotation();
    }

    private void scheduleRotation() {
        AlarmManager am = ctx.getSystemService(AlarmManager.class);
        PendingIntent pi = PendingIntent.getBroadcast(ctx, 1, new Intent(ctx, RotateReceiver.class), PendingIntent.FLAG_IMMUTABLE);
        long now = System.currentTimeMillis();
        long next = (now / 1000 / WINDOW_S + 1) * WINDOW_S * 1000 + 2000; // justo al empezar la ventana siguiente
        am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + (next - now), pi);
    }

    private final BroadcastReceiver btState = new BroadcastReceiver() {
        @Override public void onReceive(Context c, Intent i) {
            int s = i.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1);
            if (s == BluetoothAdapter.STATE_ON) { stop(); start(); }
            else if (s == BluetoothAdapter.STATE_TURNING_OFF || s == BluetoothAdapter.STATE_OFF) { stop(); state(false); }
        }
    };

    private void state(boolean on) {
        try { report.accept(new JSONObject().put("t", "ble").put("on", on)); } catch (Exception ignored) {}
    }

    // ---------- comandos del Mac ----------

    private void startGatt() {
        if (gatt != null) return;
        gatt = ctx.getSystemService(BluetoothManager.class).openGattServer(ctx, gattCallback);
        if (gatt == null) return;
        BluetoothGattService svc = new BluetoothGattService(SERVICE, BluetoothGattService.SERVICE_TYPE_PRIMARY);
        svc.addCharacteristic(new BluetoothGattCharacteristic(COMMAND,
                BluetoothGattCharacteristic.PROPERTY_WRITE, BluetoothGattCharacteristic.PERMISSION_WRITE));
        svc.addCharacteristic(new BluetoothGattCharacteristic(TUNNEL,
                BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ));
        gatt.addService(svc);
    }

    private final BluetoothGattServerCallback gattCallback = new BluetoothGattServerCallback() {
        @Override
        public void onCharacteristicReadRequest(BluetoothDevice d, int req, int offset, BluetoothGattCharacteristic ch) {
            android.bluetooth.BluetoothServerSocket s = l2cap;
            if (!TUNNEL.equals(ch.getUuid()) || s == null) { respond(d, req, BluetoothGatt.GATT_READ_NOT_PERMITTED, offset, null); return; }
            int psm = s.getPsm();
            byte[] v = new byte[] { (byte) (psm >> 8), (byte) psm };
            respond(d, req, BluetoothGatt.GATT_SUCCESS, offset, offset >= v.length ? new byte[0] : Arrays.copyOfRange(v, offset, v.length));
        }

        @Override
        public void onCharacteristicWriteRequest(BluetoothDevice d, int req, BluetoothGattCharacteristic ch,
                                                 boolean preparedWrite, boolean needResponse, int offset, byte[] value) {
            boolean ok = true;
            if (preparedWrite) {
                synchronized (prepared) {
                    byte[] cur = prepared.getOrDefault(d.getAddress(), new byte[0]);
                    byte[] n = Arrays.copyOf(cur, Math.max(cur.length, offset + value.length));
                    System.arraycopy(value, 0, n, offset, value.length);
                    prepared.put(d.getAddress(), n);
                }
            } else {
                ok = COMMAND.equals(ch.getUuid()) && command(value);
            }
            if (needResponse) respond(d, req, ok ? BluetoothGatt.GATT_SUCCESS : BluetoothGatt.GATT_WRITE_NOT_PERMITTED, offset, value);
        }

        @Override
        public void onExecuteWrite(BluetoothDevice d, int req, boolean execute) {
            byte[] v;
            synchronized (prepared) { v = prepared.remove(d.getAddress()); }
            boolean ok = !execute || (v != null && command(v));
            respond(d, req, ok ? BluetoothGatt.GATT_SUCCESS : BluetoothGatt.GATT_WRITE_NOT_PERMITTED, 0, null);
        }
    };

    private void respond(BluetoothDevice d, int req, int status, int offset, byte[] value) {
        try { gatt.sendResponse(d, req, status, offset, value); } catch (Exception ignored) {}
    }

    /** [comando][segundos unix, 8 bytes][HMAC(llave, 'C' + comando + segundos), 16 bytes] */
    private synchronized boolean command(byte[] v) {
        if (key == null || v == null || v.length != 25) return false;
        long ts = ByteBuffer.wrap(v, 1, 8).getLong();
        long now = System.currentTimeMillis() / 1000;
        if (Math.abs(now - ts) > 120 || ts <= lastCmdTs) return false; // viejo o repetido
        byte[] expect = Arrays.copyOf(hmac(ByteBuffer.allocate(10).put((byte) 'C').put(v[0]).putLong(ts).array()), 16);
        if (!MessageDigest.isEqual(expect, Arrays.copyOfRange(v, 9, 25))) return false;
        lastCmdTs = ts;
        if (v[0] == 3) return WifiDebug.request(ctx); // el Mac necesita adb (p. ej. tras reiniciar el celular)
        final boolean on = v[0] == 1;
        if (v[0] != 1 && v[0] != 2) return false;
        new Thread(() -> daemon("{\"c\":\"hotspot\",\"on\":" + on + "}"), "hotspot").start();
        return true;
    }

    private JSONObject daemon(String cmd) { return DaemonClient.ask(ctx, cmd); }

    // ---------- túnel L2CAP ----------

    /**
     * Para cuando el Mac no puede llegar al celular por la red (p. ej. un VPN con "kill switch" bloquea la red local):
     * cada canal L2CAP se reenvía tal cual al enlace del residente (127.0.0.1:47930). El cifrado va de punta a punta
     * con la llave compartida, así que el canal no necesita emparejamiento.
     */
    private void startTunnel(BluetoothAdapter a) {
        if (l2cap != null) return;
        try { l2cap = a.listenUsingInsecureL2capChannel(); }
        catch (Exception e) { l2cap = null; return; }
        final android.bluetooth.BluetoothServerSocket server = l2cap;
        Thread t = new Thread(() -> {
            while (true) {
                android.bluetooth.BluetoothSocket bt;
                try { bt = server.accept(); } catch (Exception e) { return; } // cerrado (Bluetooth apagado)
                new Thread(() -> bridge(bt), "l2cap-client").start();
            }
        }, "l2cap");
        t.setDaemon(true);
        t.start();
    }

    private static void bridge(android.bluetooth.BluetoothSocket bt) {
        Socket tcp = null;
        try {
            tcp = new Socket(InetAddress.getByName("127.0.0.1"), 47930);
            tcp.setTcpNoDelay(true);
            final Socket t = tcp;
            Thread up = new Thread(() -> pipe(bt, t, true), "l2cap-up");
            up.start();
            pipe(bt, t, false);
            up.join();
        } catch (Exception ignored) {
        } finally {
            try { bt.close(); } catch (Exception ignored) {}
            try { if (tcp != null) tcp.close(); } catch (Exception ignored) {}
        }
    }

    /** Copia en una dirección; al terminar cierra ambos lados para que la otra dirección también termine. */
    private static void pipe(android.bluetooth.BluetoothSocket bt, Socket tcp, boolean fromBt) {
        byte[] buf = new byte[16384];
        try {
            java.io.InputStream in = fromBt ? bt.getInputStream() : tcp.getInputStream();
            OutputStream out = fromBt ? tcp.getOutputStream() : bt.getOutputStream();
            int n;
            while ((n = in.read(buf)) > 0) { out.write(buf, 0, n); out.flush(); }
        } catch (Exception ignored) {}
        try { bt.close(); } catch (Exception ignored) {}
        try { tcp.close(); } catch (Exception ignored) {}
    }

    // ---------- utilidades ----------

    private byte[] hmac(byte[] msg) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(msg);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static byte[] hexToBytes(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}
