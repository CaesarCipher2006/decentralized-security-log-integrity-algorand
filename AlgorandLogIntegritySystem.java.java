import com.algorand.algosdk.account.Account;
import com.algorand.algosdk.crypto.Address;
import com.algorand.algosdk.transaction.SignedTransaction;
import com.algorand.algosdk.transaction.Transaction;
import com.algorand.algosdk.util.Encoder;
import com.algorand.algosdk.v2.client.common.AlgodClient;
import com.algorand.algosdk.v2.client.model.NodeStatusResponse;
import com.algorand.algosdk.v2.client.model.PendingTransactionResponse;
import com.algorand.algosdk.v2.client.model.PostTransactionsResponse;
import com.algorand.algosdk.v2.client.model.TransactionParametersResponse;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AlgorandLogIntegritySystem {

    private static final int PORT = 8080;

    private static final String DB_URL = System.getenv().getOrDefault(
            "DB_URL", "jdbc:mysql://localhost:3306/algorand_logs?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
    private static final String DB_USER = System.getenv().getOrDefault("DB_USER", "root");
    private static final String DB_PASS = System.getenv().getOrDefault("DB_PASS", "root");

    private static final String ALGOD_API_ADDR = "https://testnet-api.algonode.cloud";
    private static final int ALGOD_API_PORT = 443;
    private static final String ALGOD_API_TOKEN = "";

    private static final String ALGORAND_TESTNET_MNEMONIC = System.getenv().getOrDefault(
            "ALGO_MNEMONIC", "PASTE_YOUR_25_WORD_ALGORAND_TESTNET_MNEMONIC_HERE");

    private static AlgodClient algodClient;
    private static Account signerAccount = null;
    private static volatile long currentAlgorandRound = 44892104L;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static void main(String[] args) {
        try {
            System.out.println("-----------------------------------------------------------------");
            System.out.println(" Decentralized Security Log Integrity System Using Algorand");
            System.out.println("-----------------------------------------------------------------");

            initAlgorandWallet();

            DatabaseRepository repository = new DatabaseRepository(DB_URL, DB_USER, DB_PASS);
            repository.initializeSchema();

            if (repository.countLogs() == 0) {
                repository.insertLog(createAnchoredLog("INFO", "kernel-audit",
                        "System boot integrity verified; auditd daemon initialized"));
                repository.insertLog(createAnchoredLog("CRITICAL", "sshd-auth",
                        "Multiple failed SSH authentication attempts from 198.51.100.77"));
            }

            HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
            server.createContext("/", new FrontendUiHandler());
            server.createContext("/api/logs", new LogsRestController(repository));
            server.createContext("/api/logs/tamper", new TamperSimulationController(repository));
            server.createContext("/api/logs/restore", new RestoreLogController(repository));
            server.createContext("/api/algorand/status", new AlgorandStatusController());

            server.setExecutor(Executors.newFixedThreadPool(10));
            server.start();

            System.out.println("[OK] Web Console : http://localhost:" + PORT);
            System.out.println("[OK] SQL Storage : " + DB_URL);
            System.out.println("[OK] Wallet Mode : " + (signerAccount != null
                    ? "LIVE TESTNET SIGNING (" + signerAccount.getAddress() + ")"
                    : "SIMULATED TX MODE (Add 25-word mnemonic to sign live TestNet TXs)"));

        } catch (Exception e) {
            System.err.println("[ERROR] Server startup failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void initAlgorandWallet() {
        algodClient = new AlgodClient(ALGOD_API_ADDR, ALGOD_API_PORT, ALGOD_API_TOKEN);
        try {
            if (ALGORAND_TESTNET_MNEMONIC != null
                    && !ALGORAND_TESTNET_MNEMONIC.startsWith("PASTE_")
                    && ALGORAND_TESTNET_MNEMONIC.trim().split("\\s+").length == 25) {
                signerAccount = new Account(ALGORAND_TESTNET_MNEMONIC.trim());
                System.out.println("[OK] Loaded Algorand Signer Address: " + signerAccount.getAddress());
            }
        } catch (Exception e) {
            System.err.println("[WARN] Invalid mnemonic provided; falling back to simulated TxIDs: " + e.getMessage());
            signerAccount = null;
        }
        syncAlgorandRound();
    }

    public static boolean syncAlgorandRound() {
        try {
            NodeStatusResponse status = algodClient.GetStatus().execute().body();
            if (status != null && status.lastRound != null) {
                currentAlgorandRound = status.lastRound;
                return true;
            }
        } catch (Exception ignored) {
            currentAlgorandRound++;
        }
        return false;
    }

    public static AnchorReceipt anchorHashToAlgorand(String sha256Hash, String severity, String source) {
        if (signerAccount != null) {
            try {
                TransactionParametersResponse params = algodClient.TransactionParams().execute().body();
                Address sender = signerAccount.getAddress();

                String notePayload = String.format("ALGOLOG|v1|%s|%s|%s", severity, source, sha256Hash);
                byte[] noteBytes = notePayload.getBytes(StandardCharsets.UTF_8);

                Transaction txn = Transaction.PaymentTransactionBuilder()
                        .sender(sender)
                        .receiver(sender)
                        .amount(0)
                        .note(noteBytes)
                        .lookupParams(params)
                        .build();

                SignedTransaction signedTxn = signerAccount.signTransaction(txn);
                byte[] encodedTxBytes = Encoder.encodeToMsgPack(signedTxn);

                PostTransactionsResponse txResponse = algodClient.RawTransaction()
                        .rawtxn(encodedTxBytes)
                        .execute()
                        .body();

                String txId = txResponse.txId;
                long confirmedRound = waitForConfirmation(txId, 6);
                if (confirmedRound > 0) {
                    currentAlgorandRound = confirmedRound;
                }
                return new AnchorReceipt(txId, currentAlgorandRound, sender.toString(), true);

            } catch (Exception e) {
                System.err.println("[WARN] Live TestNet broadcast failed (" + e.getMessage() + "), using fallback receipt.");
            }
        }

        syncAlgorandRound();
        currentAlgorandRound++;
        return new AnchorReceipt(generateBase32TxId(), currentAlgorandRound, "UNCONFIGURED_DEMO_WALLET", false);
    }

    private static long waitForConfirmation(String txId, int timeoutRounds) throws Exception {
        NodeStatusResponse status = algodClient.GetStatus().execute().body();
        long startRound = status.lastRound + 1;
        long currentRound = startRound;

        while (currentRound < startRound + timeoutRounds) {
            PendingTransactionResponse pending = algodClient.PendingTransactionInformation(txId).execute().body();
            if (pending != null) {
                if (pending.confirmedRound != null && pending.confirmedRound > 0) {
                    return pending.confirmedRound;
                }
                if (pending.poolError != null && !pending.poolError.isEmpty()) {
                    throw new RuntimeException("Algorand pool error: " + pending.poolError);
                }
            }
            algodClient.WaitForBlock(currentRound).execute();
            currentRound++;
        }
        return currentAlgorandRound;
    }

    public static String computeSha256(String rawInput) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(rawInput.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
            for (byte b : encodedHash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String generateBase32TxId() {
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder sb = new StringBuilder(52);
        for (int i = 0; i < 52; i++) {
            sb.append(alphabet.charAt(SECURE_RANDOM.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    public static SecurityLogRecord createAnchoredLog(String severity, String source, String message) {
        String canonical = String.format("[%s] [%s] %s", severity, source, message);
        String sha256Hash = computeSha256(canonical);
        AnchorReceipt receipt = anchorHashToAlgorand(sha256Hash, severity, source);
        String timestamp = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));

        return new SecurityLogRecord(
                UUID.randomUUID().toString(),
                severity,
                source,
                message,
                message,
                sha256Hash,
                receipt.txId,
                receipt.signerAddress,
                receipt.liveOnChain,
                receipt.confirmedRound,
                timestamp,
                System.currentTimeMillis()
        );
    }

    public record AnchorReceipt(String txId, long confirmedRound, String signerAddress, boolean liveOnChain) {}

    public static class SecurityLogRecord {
        public final String id;
        public final String severity;
        public final String source;
        public final String originalMessage;
        public final String currentMessage;
        public final String anchoredHash;
        public final String txId;
        public final String signerAddress;
        public final boolean liveOnChain;
        public final long blockRound;
        public final String timestamp;
        public final long createdAt;

        public SecurityLogRecord(String id, String severity, String source, String originalMessage,
                                 String currentMessage, String anchoredHash, String txId,
                                 String signerAddress, boolean liveOnChain,
                                 long blockRound, String timestamp, long createdAt) {
            this.id = id;
            this.severity = severity;
            this.source = source;
            this.originalMessage = originalMessage;
            this.currentMessage = currentMessage;
            this.anchoredHash = anchoredHash;
            this.txId = txId;
            this.signerAddress = signerAddress;
            this.liveOnChain = liveOnChain;
            this.blockRound = blockRound;
            this.timestamp = timestamp;
            this.createdAt = createdAt;
        }

        public String toJson() {
            String recomputedPayload = String.format("[%s] [%s] %s", severity, source, currentMessage);
            String recomputedHash = computeSha256(recomputedPayload);
            boolean intact = recomputedHash.equals(anchoredHash);

            return "{"
                    + "\"id\":\"" + escapeJson(id) + "\","
                    + "\"severity\":\"" + escapeJson(severity) + "\","
                    + "\"source\":\"" + escapeJson(source) + "\","
                    + "\"originalMessage\":\"" + escapeJson(originalMessage) + "\","
                    + "\"currentMessage\":\"" + escapeJson(currentMessage) + "\","
                    + "\"anchoredHash\":\"" + escapeJson(anchoredHash) + "\","
                    + "\"recomputedHash\":\"" + escapeJson(recomputedHash) + "\","
                    + "\"intact\":" + intact + ","
                    + "\"txId\":\"" + escapeJson(txId) + "\","
                    + "\"signerAddress\":\"" + escapeJson(signerAddress) + "\","
                    + "\"liveOnChain\":" + liveOnChain + ","
                    + "\"blockRound\":" + blockRound + ","
                    + "\"timestamp\":\"" + escapeJson(timestamp) + "\""
                    + "}";
        }
    }

    public static class DatabaseRepository {
        private final String jdbcUrl;
        private final String dbUser;
        private final String dbPass;

        public DatabaseRepository(String jdbcUrl, String dbUser, String dbPass) {
            this.jdbcUrl = jdbcUrl;
            this.dbUser = dbUser;
            this.dbPass = dbPass;
        }

        private Connection getConnection() throws SQLException {
            if (jdbcUrl.startsWith("jdbc:sqlite:")) {
                return DriverManager.getConnection(jdbcUrl);
            }
            return DriverManager.getConnection(jdbcUrl, dbUser, dbPass);
        }

        public void initializeSchema() throws SQLException {
            String ddl = """
                CREATE TABLE IF NOT EXISTS security_logs (
                    id VARCHAR(64) PRIMARY KEY,
                    severity VARCHAR(16) NOT NULL,
                    source VARCHAR(64) NOT NULL,
                    original_message TEXT NOT NULL,
                    current_message TEXT NOT NULL,
                    anchored_hash CHAR(64) NOT NULL,
                    tx_id VARCHAR(64) NOT NULL,
                    signer_address VARCHAR(64) NOT NULL,
                    live_on_chain BOOLEAN NOT NULL,
                    block_round BIGINT NOT NULL,
                    timestamp VARCHAR(16) NOT NULL,
                    created_at BIGINT NOT NULL
                )
                """;
            try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
                stmt.execute(ddl);
            }
        }

        public int countLogs() throws SQLException {
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM security_logs")) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }

        public synchronized void insertLog(SecurityLogRecord record) throws SQLException {
            String sql = """
                INSERT INTO security_logs (
                    id, severity, source, original_message, current_message,
                    anchored_hash, tx_id, signer_address, live_on_chain,
                    block_round, timestamp, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
            try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, record.id);
                ps.setString(2, record.severity);
                ps.setString(3, record.source);
                ps.setString(4, record.originalMessage);
                ps.setString(5, record.currentMessage);
                ps.setString(6, record.anchoredHash);
                ps.setString(7, record.txId);
                ps.setString(8, record.signerAddress);
                ps.setBoolean(9, record.liveOnChain);
                ps.setLong(10, record.blockRound);
                ps.setString(11, record.timestamp);
                ps.setLong(12, record.createdAt);
                ps.executeUpdate();
            }
        }

        public List<SecurityLogRecord> findAllOrderedByNewest() throws SQLException {
            List<SecurityLogRecord> list = new ArrayList<>();
            String sql = "SELECT * FROM security_logs ORDER BY created_at DESC";
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {
                while (rs.next()) {
                    list.add(new SecurityLogRecord(
                            rs.getString("id"),
                            rs.getString("severity"),
                            rs.getString("source"),
                            rs.getString("original_message"),
                            rs.getString("current_message"),
                            rs.getString("anchored_hash"),
                            rs.getString("tx_id"),
                            rs.getString("signer_address"),
                            rs.getBoolean("live_on_chain"),
                            rs.getLong("block_round"),
                            rs.getString("timestamp"),
                            rs.getLong("created_at")
                    ));
                }
            }
            return list;
        }

        public synchronized void simulateDatabaseTamper(String id) throws SQLException {
            String selectSql = "SELECT current_message FROM security_logs WHERE id = ?";
            String updateSql = "UPDATE security_logs SET current_message = ? WHERE id = ?";
            try (Connection conn = getConnection();
                 PreparedStatement selectPs = conn.prepareStatement(selectSql)) {
                selectPs.setString(1, id);
                try (ResultSet rs = selectPs.executeQuery()) {
                    if (rs.next()) {
                        String current = rs.getString("current_message");
                        String tampered = current.replaceAll("\\d+", "0") + " [MODIFIED_IN_SQL]";
                        try (PreparedStatement updatePs = conn.prepareStatement(updateSql)) {
                            updatePs.setString(1, tampered);
                            updatePs.setString(2, id);
                            updatePs.executeUpdate();
                        }
                    }
                }
            }
        }

        public synchronized void restoreOriginalLog(String id) throws SQLException {
            String sql = "UPDATE security_logs SET current_message = original_message WHERE id = ?";
            try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, id);
                ps.executeUpdate();
            }
        }

        public synchronized void deleteAllLogs() throws SQLException {
            try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("DELETE FROM security_logs");
            }
        }
    }

    static class LogsRestController implements HttpHandler {
        private final DatabaseRepository repository;

        LogsRestController(DatabaseRepository repository) {
            this.repository = repository;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String method = exchange.getRequestMethod();
                if ("GET".equalsIgnoreCase(method)) {
                    List<SecurityLogRecord> logs = repository.findAllOrderedByNewest();
                    StringBuilder json = new StringBuilder("[");
                    for (int i = 0; i < logs.size(); i++) {
                        json.append(logs.get(i).toJson());
                        if (i < logs.size() - 1) json.append(",");
                    }
                    json.append("]");
                    sendJson(exchange, 200, json.toString());

                } else if ("POST".equalsIgnoreCase(method)) {
                    String body = readRequestBody(exchange);
                    String severity = extractJsonField(body, "severity", "INFO");
                    String source = extractJsonField(body, "source", "sshd-auth");
                    String message = extractJsonField(body, "message", "");

                    if (message.isBlank()) {
                        sendJson(exchange, 400, "{\"error\":\"Log message required\"}");
                        return;
                    }

                    SecurityLogRecord record = createAnchoredLog(severity, source, message);
                    repository.insertLog(record);
                    sendJson(exchange, 201, record.toJson());

                } else if ("DELETE".equalsIgnoreCase(method)) {
                    repository.deleteAllLogs();
                    sendJson(exchange, 200, "{\"status\":\"cleared\"}");
                } else {
                    sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                }
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    static class TamperSimulationController implements HttpHandler {
        private final DatabaseRepository repository;

        TamperSimulationController(DatabaseRepository repository) {
            this.repository = repository;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String id = extractJsonField(readRequestBody(exchange), "id", "");
                repository.simulateDatabaseTamper(id);
                sendJson(exchange, 200, "{\"status\":\"tampered\"}");
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    static class RestoreLogController implements HttpHandler {
        private final DatabaseRepository repository;

        RestoreLogController(DatabaseRepository repository) {
            this.repository = repository;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String id = extractJsonField(readRequestBody(exchange), "id", "");
                repository.restoreOriginalLog(id);
                sendJson(exchange, 200, "{\"status\":\"restored\"}");
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    static class AlgorandStatusController implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            boolean synced = syncAlgorandRound();
            String wallet = signerAccount != null ? signerAccount.getAddress().toString() : "NOT_CONFIGURED (SIMULATED)";
            String json = String.format(
                    "{\"round\":%d,\"synced\":%b,\"wallet\":\"%s\",\"liveSigning\":%b,\"dbUrl\":\"%s\"}",
                    currentAlgorandRound,
                    synced,
                    escapeJson(wallet),
                    signerAccount != null,
                    escapeJson(DB_URL.split("\\?")[0])
            );
            sendJson(exchange, 200, json);
        }
    }

    static class FrontendUiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>AlgoLogGuard — Security Log Integrity Console</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="bg-[#0d1117] text-[#c9d1d9] font-sans antialiased">
                    <div class="border-b border-[#30363d] bg-[#161b22] px-6 py-3 flex flex-wrap items-center justify-between gap-4">
                        <div class="flex items-center gap-3">
                            <span class="px-2 py-0.5 bg-[#238636] text-white text-xs font-mono font-bold rounded">JAVA + SQL</span>
                            <h1 class="font-semibold text-white text-base">Decentralized Security Log Integrity System Using Algorand</h1>
                        </div>
                        <div class="text-xs font-mono text-[#8b949e]">
                            Algorand TestNet Round: <span id="round" class="text-[#58a6ff] font-bold">Loading...</span>
                        </div>
                    </div>

                    <div class="max-w-7xl mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
                        <div class="lg:col-span-4 space-y-4">
                            <div class="bg-[#161b22] border border-[#30363d] rounded-md p-5">
                                <h2 class="text-sm font-semibold text-white uppercase tracking-wider mb-4">Ingest Security Event</h2>
                                <form id="form" class="space-y-3">
                                    <div class="grid grid-cols-2 gap-2">
                                        <select id="sev" class="bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-xs text-white">
                                            <option value="CRITICAL">CRITICAL</option>
                                            <option value="WARNING">WARNING</option>
                                            <option value="INFO" selected>INFO</option>
                                        </select>
                                        <select id="src" class="bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-xs text-white">
                                            <option value="sshd-auth">sshd-auth</option>
                                            <option value="firewall-edge">firewall-edge</option>
                                            <option value="mysql-audit">mysql-audit</option>
                                        </select>
                                    </div>
                                    <textarea id="msg" rows="3" required class="w-full bg-[#0d1117] border border-[#30363d] rounded p-2.5 text-xs font-mono text-white">Failed password for root from 103.42.91.14 port 48912 ssh2</textarea>
                                    <button type="submit" class="w-full py-2.5 bg-[#238636] hover:bg-[#2ea043] text-white font-semibold text-xs rounded">
                                        Hash (SHA-256) & Anchor to Algorand
                                    </button>
                                </form>
                            </div>
                            <div class="bg-[#161b22] border border-[#30363d] rounded-md p-4 text-xs font-mono space-y-1.5">
                                <div class="text-[#8b949e] font-bold">SYSTEM TELEMETRY</div>
                                <div>SQL JDBC: <span id="db-info" class="text-[#c9d1d9]">...</span></div>
                                <div>Signer Wallet: <span id="wallet-info" class="text-[#58a6ff] break-all">...</span></div>
                            </div>
                        </div>

                        <div class="lg:col-span-8 bg-[#161b22] border border-[#30363d] rounded-md p-5">
                            <div class="flex items-center justify-between mb-4">
                                <h2 class="text-sm font-semibold text-white uppercase tracking-wider">SQL Database vs. Algorand Ledger Audit</h2>
                                <button id="clear" class="px-3 py-1 bg-[#21262d] hover:bg-[#da3633]/20 border border-[#30363d] text-xs rounded">Truncate SQL Table</button>
                            </div>
                            <div id="list" class="space-y-3"></div>
                        </div>
                    </div>

                    <script>
                        async function refreshStatus() {
                            const r = await (await fetch('/api/algorand/status')).json();
                            document.getElementById('round').textContent = '#' + r.round.toLocaleString();
                            document.getElementById('db-info').textContent = r.dbUrl;
                            document.getElementById('wallet-info').textContent = r.wallet;
                        }
                        async function load() {
                            const logs = await (await fetch('/api/logs')).json();
                            document.getElementById('list').innerHTML = logs.map(l => `
                                <div class="p-4 bg-[#0d1117] border ${l.intact ? 'border-[#30363d]' : 'border-[#f85149]'} rounded-md text-xs">
                                    <div class="flex justify-between items-center mb-2">
                                        <span class="font-mono"><strong class="text-white">[${l.severity}]</strong> ${l.source} • ${l.timestamp}</span>
                                        <span class="px-2 py-0.5 rounded font-mono font-bold ${l.intact ? 'bg-[#238636]/20 text-[#3fb950]' : 'bg-[#da3633]/20 text-[#f85149]'}">
                                            ${l.intact ? 'INTACT' : 'HASH MISMATCH'}
                                        </span>
                                    </div>
                                    <div class="p-2 bg-[#161b22] border border-[#30363d] rounded font-mono text-white mb-2">${l.currentMessage}</div>
                                    <div class="font-mono text-[11px] text-[#8b949e] space-y-0.5">
                                        <div>Algorand TxID (Round #${l.blockRound}): <a target="_blank" href="https://testnet.explorer.perawallet.app/tx/${l.txId}" class="text-[#58a6ff] underline">${l.txId}</a></div>
                                        <div>On-Chain SHA-256 : ${l.anchoredHash}</div>
                                        <div>SQL Recomputed   : <span class="${l.intact ? 'text-[#3fb950]' : 'text-[#f85149]'}">${l.recomputedHash}</span></div>
                                    </div>
                                    <div class="mt-2.5 flex justify-end">
                                        ${l.intact
                                            ? `<button onclick="act('tamper','${l.id}')" class="px-2.5 py-1 bg-[#da3633]/10 border border-[#f85149]/40 text-[#f85149] rounded">Simulate SQL Tamper</button>`
                                            : `<button onclick="act('restore','${l.id}')" class="px-2.5 py-1 bg-[#238636]/20 border border-[#3fb950]/40 text-[#3fb950] rounded">Restore SQL Row</button>`}
                                    </div>
                                </div>
                            `).join('');
                        }
                        async function act(type, id) {
                            await fetch('/api/logs/' + type, { method: 'POST', body: JSON.stringify({ id }) });
                            load();
                        }
                        document.getElementById('form').onsubmit = async (e) => {
                            e.preventDefault();
                            await fetch('/api/logs', { method: 'POST', body: JSON.stringify({
                                severity: document.getElementById('sev').value,
                                source: document.getElementById('src').value,
                                message: document.getElementById('msg').value
                            })});
                            refreshStatus(); load();
                        };
                        document.getElementById('clear').onclick = async () => {
                            await fetch('/api/logs', { method: 'DELETE' });
                            load();
                        };
                        refreshStatus(); load();
                    </script>
                </body>
                </html>
                """.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, html.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(html);
            }
        }
    }

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String extractJsonField(String json, String key, String fallback) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\\"|[^\"])*)\"").matcher(json);
        return m.find() ? m.group(1).replace("\\\"", "\"").replace("\\n", "\n") : fallback;
    }

    private static String escapeJson(String val) {
        if (val == null) return "";
        return val.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}