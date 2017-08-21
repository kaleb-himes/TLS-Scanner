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
import org.apache.logging.log4j.core.config.Configurator;

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
                /*
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
                 */
                File hostList = new File("C:\\SVN\\literature\\hosts.txt");
                scanFile(hostList);
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
        StringBuilder resultCsvString = new StringBuilder();
        resultCsvString.append("host,encryptThenMac,extendedMasterSecret,maxFragmentLength9,maxFragmentLength10,maxFragmentLength11,maxFragmentLength12,"
                + "certType,clientAuthz,clientCertUrl,renegotiationInfo,sessionTicket,truncatedHmac,useSrtp,tok1,"
                + "tok2,tok3,tok4,tok5,tok6,tok7,tok8,tok9,tok10,tok11,tok12,tok13,tok14,tok15\r\n");
        GeneralDelegate delegate = new GeneralDelegate();
        delegate.setLogLevel(Level.OFF);
        Configurator.setRootLevel(Level.OFF);
        String test = "google.com\n"
                + "netflix.com\n"
                + "api-global.netflix.com\n"
                + "microsoft.com\n"
                + "www.google.com\n"
                + "hola.org\n"
                + "dns-test1.hola.org\n"
                + "facebook.com\n"
                + "doubleclick.net\n"
                + "g.doubleclick.net\n"
                + "ichnaea.netflix.com\n"
                + "googleads.g.doubleclick.net\n"
                + "youtube.com\n"
                + "data.microsoft.com\n"
                + "clients4.google.com\n"
                + "google-analytics.com\n"
                + "secure.netflix.com\n"
                + "www.facebook.com\n"
                + "appboot.netflix.com\n"
                + "www.googleapis.com\n"
                + "fbcdn.net\n"
                + "settings-win.data.microsoft.com\n"
                + "graph.facebook.com\n"
                + "www.youtube.com\n"
                + "amazonaws.com\n"
                + "apple.com\n"
                + "safebrowsing.googleapis.com\n"
                + "googleadservices.com\n"
                + "googlesyndication.com\n"
                + "www.google-analytics.com\n"
                + "www.googleadservices.com\n"
                + "ytimg.com\n"
                + "nccp.netflix.com\n"
                + "xx.fbcdn.net\n"
                + "live.com\n"
                + "nrdp.nccp.netflix.com\n"
                + "googleusercontent.com\n"
                + "pagead2.googlesyndication.com\n"
                + "clientservices.googleapis.com\n"
                + "fonts.googleapis.com\n"
                + "i.ytimg.com\n"
                + "ipv6.microsoft.com\n"
                + "clients.google.com\n"
                + "googlevideo.com\n"
                + "akadns.net\n"
                + "play.googleapis.com\n"
                + "clients1.google.com\n"
                + "crl.microsoft.com\n"
                + "android.clients.google.com\n"
                + "yahoo.com\n"
                + "accounts.google.com\n"
                + "bing.com\n"
                + "mtalk.google.com\n"
                + "apis.google.com\n"
                + "com.akadns.net\n"
                + "securepubads.g.doubleclick.net\n"
                + "vortex-win.data.microsoft.com\n"
                + "tpc.googlesyndication.com\n"
                + "msn.com\n"
                + "ntp.org\n"
                + "pool.ntp.org\n"
                + "twitter.com\n"
                + "clients3.google.com\n"
                + "akamaiedge.net\n"
                + "ggpht.com\n"
                + "l.google.com\n"
                + "s.youtube.com\n"
                + "facebook.net\n"
                + "connect.facebook.net\n"
                + "edge-mqtt.facebook.com\n"
                + "scorecardresearch.com\n"
                + "icloud.com\n"
                + "play.google.com\n"
                + "v10.vortex-win.data.microsoft.com\n"
                + "www.apple.com\n"
                + "stats.g.doubleclick.net\n"
                + "instagram.com\n"
                + "clients2.google.com\n"
                + "ssl.google-analytics.com\n"
                + "itunes.apple.com\n"
                + "lh3.googleusercontent.com\n"
                + "skype.com\n"
                + "crashlytics.com\n"
                + "push.apple.com\n"
                + "yt3.ggpht.com\n"
                + "cm.g.doubleclick.net\n"
                + "symcd.com\n"
                + "whatsapp.net\n"
                + "adnxs.com\n"
                + "update.microsoft.com\n"
                + "2mdn.net\n"
                + "akamai.net\n"
                + "googletagservices.com\n"
                + "login.live.com\n"
                + "www.googletagservices.com\n"
                + "static.xx.fbcdn.net\n"
                + "windowsupdate.com\n"
                + "apple-dns.net\n"
                + "ad.doubleclick.net\n"
                + "msftncsi.com\n"
                + "scontent.xx.fbcdn.net\n"
                + "tools.google.com\n"
                + "fe.apple-dns.net\n"
                + "ls.apple.com\n"
                + "ajax.googleapis.com\n"
                + "staticxx.facebook.com\n"
                + "time-ios.apple.com\n"
                + "settings.crashlytics.com\n"
                + "pubads.g.doubleclick.net\n"
                + "guzzoni.apple.com\n"
                + "s0.2mdn.net\n"
                + "twimg.com\n"
                + "fna.fbcdn.net\n"
                + "teredo.ipv6.microsoft.com\n"
                + "googletagmanager.com\n"
                + "www.googletagmanager.com\n"
                + "init-p01st.push.apple.com\n"
                + "app-measurement.com\n"
                + "s.ytimg.com\n"
                + "translate.googleapis.com\n"
                + "update.googleapis.com\n"
                + "www.icloud.com\n"
                + "c10r.facebook.com\n"
                + "weather.microsoft.com\n"
                + "msedge.net\n"
                + "criteo.com\n"
                + "notifications.google.com\n"
                + "officeapps.live.com\n"
                + "digicert.com\n"
                + "aaplimg.com\n"
                + "g.aaplimg.com\n"
                + "mqtt-mini.facebook.com\n"
                + "mp.microsoft.com\n"
                + "graph.instagram.com\n"
                + "sb.scorecardresearch.com\n"
                + "bluekai.com\n"
                + "fe2.update.microsoft.com\n"
                + "edge.skype.com\n"
                + "akamaihd.net\n"
                + "init.itunes.apple.com\n"
                + "ib.adnxs.com\n"
                + "agkn.com\n"
                + "static.doubleclick.net\n"
                + "edgekey.net\n"
                + "amazon.com\n"
                + "e.crashlytics.com\n"
                + "dns.msftncsi.com\n"
                + "android.pool.ntp.org\n"
                + "2.android.pool.ntp.org\n"
                + "www.bing.com\n"
                + "com.edgekey.net\n"
                + "dsce9.akamaiedge.net\n"
                + "e6858.dsce9.akamaiedge.net\n"
                + "xp.apple.com\n"
                + "rubiconproject.com\n"
                + "ocsp.digicert.com\n"
                + "tile-service.weather.microsoft.com\n"
                + "mathtag.com\n"
                + "mail.google.com\n"
                + "youtubei.googleapis.com\n"
                + "adsrvr.org\n"
                + "platform.twitter.com\n"
                + "ctldl.windowsupdate.com\n"
                + "moatads.com\n"
                + "b-api.facebook.com\n"
                + "outlook.com\n"
                + "cms.msn.com\n"
                + "prod.cms.msn.com\n"
                + "content.prod.cms.msn.com\n"
                + "cdn.content.prod.cms.msn.com\n"
                + "windows.com\n"
                + "b.scorecardresearch.com\n"
                + "mookie1.com\n"
                + "demdex.net\n"
                + "tags.bluekai.com\n"
                + "advertising.com\n"
                + "config.edge.skype.com\n"
                + "openx.net\n"
                + "onenote.net\n"
                + "cdn.onenote.net\n"
                + "addthis.com\n"
                + "bidswitch.net\n"
                + "b-graph.facebook.com\n"
                + "nexusrules.officeapps.live.com\n"
                + "rlcdn.com\n"
                + "googleads4.g.doubleclick.net\n"
                + "match.adsrvr.org\n"
                + "smoot.apple.com\n"
                + "pki.google.com\n"
                + "cloudflare.com\n"
                + "x.bidswitch.net\n"
                + "d.agkn.com\n"
                + "clients5.google.com\n"
                + "safebrowsing.google.com\n"
                + "android.googleapis.com\n"
                + "time-ios.g.aaplimg.com\n"
                + "us-east-1.elb.amazonaws.com\n"
                + "quantserve.com\n"
                + "aria.microsoft.com\n"
                + "pipe.aria.microsoft.com\n"
                + "ogs.google.com\n"
                + "dpm.demdex.net\n"
                + "i9.ytimg.com\n"
                + "nflximg.com\n"
                + "gsp64-ssl.ls.apple.com\n"
                + "nexus.officeapps.live.com\n"
                + "dropbox.com\n"
                + "gmail.com\n"
                + "go.microsoft.com\n"
                + "idsync.rlcdn.com\n"
                + "gsp-ssl.ls.apple.com\n"
                + "cdnjs.cloudflare.com\n"
                + "apple.com.edgekey.net\n"
                + "casalemedia.com\n"
                + "guzzoni-apple.com.akadns.net\n"
                + "star.c10r.facebook.com\n"
                + "pubmatic.com\n"
                + "adobe.com\n"
                + "gvt1.com\n"
                + "clients6.google.com\n"
                + "i1.ytimg.com\n"
                + "icloud.com.akadns.net\n"
                + "l.doubleclick.net\n"
                + "a.akamaiedge.net\n"
                + "us-u.openx.net\n"
                + "office365.com\n"
                + "amazon-adsystem.com\n"
                + "sync.mathtag.com\n"
                + "e9.akamaiedge.net\n"
                + "taboola.com\n"
                + "origin.guzzoni-apple.com.akadns.net\n"
                + "akamaized.net\n"
                + "arc.msn.com\n"
                + "avast.com\n"
                + "pinterest.com\n"
                + "odr.mookie1.com\n"
                + "lh5.googleusercontent.com\n"
                + "everesttech.net\n"
                + "www-cdn.icloud.com.akadns.net\n"
                + "api.facebook.com\n"
                + "dsp.mp.microsoft.com\n"
                + "gum.criteo.com\n"
                + "pixel.rubiconproject.com\n"
                + "imrworldwide.com\n"
                + "plus.google.com\n"
                + "serving-sys.com\n"
                + "secure.adnxs.com\n"
                + "do.dsp.mp.microsoft.com\n"
                + "tapad.com\n"
                + "crwdcntrl.net";

        String[] hosts = test.split("\n");
        delegate.applyDelegate(Config.createConfig());
        /*
        BufferedReader reader = new BufferedReader(new FileReader(f));
        String line;
        while ((line = reader.readLine()) != null) {
            String host = line;
            TLSScanner scanner = new TLSScanner(host, false);
            SiteReport report = scanner.scan();
            resultCsvString.append(report.getStringReport());
        }
         */
        for (String host : hosts) {
            TLSScanner scanner = new TLSScanner(host, false);
            SiteReport report = scanner.scan();
            resultCsvString.append(report.getStringReport());
        }
        System.out.println(resultCsvString.toString());
        System.exit(0);
    }
}
