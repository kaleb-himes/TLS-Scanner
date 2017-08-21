/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteOrderProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.probe.ProbeType;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.TLSProbe;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSScanner {

    private final ScanJobExecutor executor;
    private final ScannerConfig config;

    public TLSScanner(String websiteHost, boolean attackingScans) {
        this.executor = new ScanJobExecutor(1);
        config = new ScannerConfig(new GeneralDelegate());
        ClientDelegate clientDelegate = (ClientDelegate) config.getDelegateList().get(1);
        clientDelegate.setHost(websiteHost);
        Configurator.setRootLevel(Level.OFF);
    }

    public TLSScanner(ScannerConfig config) {
        this.executor = new ScanJobExecutor(config.getThreads());
        this.config = config;
        config.getGeneralDelegate().setLogLevel(Level.OFF);

    }

    public SiteReport scan() {
        List<TLSProbe> testList = new LinkedList<>();
        //testList.add(new CertificateProbe(config));
        //testList.add(new ProtocolVersionProbe(config));
        //testList.add(new CiphersuiteProbe(config));
        //testList.add(new CiphersuiteOrderProbe(config));
        // testList.add(new HeartbleedProbe(websiteHost));
        // testList.add(new NamedCurvesProbe(websiteHost));
        // testList.add(new PaddingOracleProbe(websiteHost));
        // testList.add(new SignatureAndHashAlgorithmProbe(websiteHost));
        testList.add(new ExtensionProbe(config));
        ScanJob job = new ScanJob(testList);
        return executor.execute(config, job);
    }

}
