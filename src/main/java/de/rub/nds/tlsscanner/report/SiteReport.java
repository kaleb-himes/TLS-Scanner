/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SiteReport {

    private final List<ProbeResult> resultList;
    private final String host;

    public SiteReport(String host, List<ProbeResult> resultList) {
        this.resultList = resultList;
        this.host = host;
    }

    public List<ProbeResult> getResultList() {
        return resultList;
    }

    public String getStringReport() {
        StringBuilder builder = new StringBuilder();
        //builder.append("Report for ");
        //builder.append(host);
        //builder.append("\n");
        for (ProbeResult result : resultList) {
            builder.append(result.toString());
            //builder.append("\n");
        }
        return builder.toString();
    }

    @Override
    public String toString() {
        return getStringReport();
    }

}
