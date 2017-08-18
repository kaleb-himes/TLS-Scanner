/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger(Main.class.getName());

    public static void main(String[] args) throws IOException {
        ScannerConfig config = new ScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            // Cmd was parsable
            try {
                TLSScanner scanner = new TLSScanner(config);
                long time = System.currentTimeMillis();
                SiteReport report = scanner.scan();
                LOGGER.info("Scanned in:" + ((System.currentTimeMillis() - time) / 1000) + "s");
                LOGGER.info(report.getStringReport());
                StringBuilder resultCsvString = new StringBuilder();
                resultCsvString.append("host,encryptThenMac,extendedMasterSecret,maxFragmentLength9,maxFragmentLength10,maxFragmentLength11,maxFragmentLength12,"
                        + "certType,clientAuthz,clientCertUrl,renegotiationInfo,sessionTicket,truncatedHmac,useSrtp,tok1,"
                        + "tok2,tok3,tok4,tok5,tok6,tok7,tok8,tok9,tok10,tok11,tok12,tok13,tok14,tok15\r\n");
                resultCsvString.append(report.getStringReport());
                System.out.println(resultCsvString.toString());
            } catch (ConfigurationException E) {
                LOGGER.info("Encountered a ConfigurationException aborting.");
                LOGGER.debug(E);
            }
        } catch (ParameterException E) {
            LOGGER.info("Could not parse provided parameters");
            LOGGER.debug(E);
            commander.usage();
        }
    }

    public static void scanFile(File f) throws FileNotFoundException, IOException {
        GeneralDelegate delegate = new GeneralDelegate();
        delegate.setLogLevel(Level.WARN);
        delegate.applyDelegate(Config.createConfig());
        BufferedReader reader = new BufferedReader(new FileReader(f));
        String line = null;
        line = reader.readLine();
        while ((line = reader.readLine()) != null) {
            String host = line.split(",")[2];
            TLSScanner scanner = new TLSScanner(host, false);
            scanner.scan();
        }
        System.exit(0);
    }
}
