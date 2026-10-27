// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 CARLOS Contributors
package io.github.carlos_emr.carlos.demographic.cdsimport;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Properties;
import java.util.regex.Pattern;

/** Synthetic boundary probe only: this deliberately contains no clinical importer. */
public final class CdsImport {
    private CdsImport() { }

    public static void main(String[] args) throws Exception {
        require(Runtime.version().feature() == 25);
        String status = Files.readString(Path.of("/proc/self/status"));
        require(Pattern.compile("(?m)^Uid:\\s+10001\\s+10001\\s+10001\\s+10001$")
                .matcher(status).find());
        require(Pattern.compile("(?m)^Gid:\\s+10001\\s+10001\\s+10001\\s+10001$")
                .matcher(status).find());
        for (String field : new String[]{"CapEff", "CapPrm", "CapBnd", "CapAmb"}) {
            require(Pattern.compile("(?m)^" + field + ":\\s+0+$").matcher(status).find());
        }
        require(Pattern.compile("(?m)^NoNewPrivs:\\s+1$").matcher(status).find());
        for (String name : new String[]{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS",
                "_JAVA_OPTIONS", "CLASSPATH", "CATALINA_OPTS"}) {
            require(System.getenv(name) == null);
        }
        Path properties = Path.of(System.getenv("CARLOS_CDS_PROPERTIES"));
        require(properties.equals(Path.of("/run/carlos-config/carlos.properties")));
        Properties config = new Properties();
        try (InputStream stream = Files.newInputStream(properties)) {
            config.load(stream);
        }
        int heap = Integer.parseInt(config.getProperty("cds.import.cliHeapMiB"));
        immutable(properties);
        if (args.length == 1 && "--capabilities".equals(args[0])) {
            require(Runtime.getRuntime().maxMemory() <= 140L * 1024 * 1024);
            System.out.println("{\"protocol\":1,\"java\":25,\"cliHeapMiB\":" + heap
                    + ",\"operations\":[\"import\",\"status\",\"resume\",\"cancel\",\"report\"]}");
            return;
        }
        require(Runtime.getRuntime().maxMemory() <= (heap + 16L) * 1024 * 1024);
        Path parent = Path.of("/run/carlos-cds-delegations");
        Path ticket = Path.of(System.getenv("CARLOS_CDS_DELEGATION_TICKET"));
        require(ticket.getParent().equals(parent));
        require(!Files.isSymbolicLink(ticket));
        require((int) Files.getAttribute(ticket, "unix:uid") == 0);
        require((int) Files.getAttribute(ticket, "unix:gid") == 10001);
        require(Files.getPosixFilePermissions(ticket).equals(PosixFilePermissions.fromString("rw-r-----")));
        require((int) Files.getAttribute(parent, "unix:uid") == 0);
        require(Files.getPosixFilePermissions(parent).equals(PosixFilePermissions.fromString("rwxr-x---")));
        immutable(ticket);
        String json = Files.readString(ticket);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (String arg : args) {
            byte[] bytes = arg.getBytes(StandardCharsets.UTF_8);
            sha.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
            sha.update(bytes);
        }
        String digest = HexFormat.of().formatHex(sha.digest());
        require(json.contains("\"argvSha256\":\"" + digest + "\""));
        require(json.contains("\"provider\":\"999998\""));
        require(json.contains("\"operator\":\"synthetic-operator\""));
        require(json.contains("\"nonce\":\"" + ticket.getFileName().toString().replace(".json", "") + "\""));
        var expiry = Pattern.compile("\"expiresEpochSeconds\":([0-9]+)").matcher(json);
        require(expiry.find() && Long.parseLong(expiry.group(1)) > Instant.now().getEpochSecond());
        immutable(Path.of("/var/lib/carlos-emr/cds-import/source/é.xml"));
        Files.writeString(Path.of("/var/lib/carlos-emr/cds-import/state/synthetic-receipt"), "receipt");
        Files.writeString(Path.of("/var/lib/CarlosDocument/synthetic-document"), "document");
        Files.createTempFile("synthetic-cds-", ".tmp");
        System.out.println("{\"syntheticBoundaryVerified\":true}");
    }

    private static void immutable(Path path) throws Exception {
        try (var ignored = Files.newOutputStream(path, StandardOpenOption.WRITE)) {
            throw new IllegalStateException("synthetic boundary: unexpectedly writable");
        } catch (java.nio.file.FileSystemException expected) {
            // Read-only mount or DAC refusal is required, not an absent source.
            require(Files.isRegularFile(path));
        }
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new IllegalStateException("synthetic CDS launcher boundary failed");
        }
    }
}
