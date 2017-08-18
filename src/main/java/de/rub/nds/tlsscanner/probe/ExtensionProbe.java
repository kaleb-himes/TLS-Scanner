/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import static de.rub.nds.tlsscanner.probe.TLSProbe.LOGGER;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ExtensionProbe extends TLSProbe {

    private final List<ProtocolVersion> protocolVersions;

    public ExtensionProbe(ScannerConfig config) {
        super(ProbeType.EXTENSION, config);
        protocolVersions = new LinkedList<>();
        protocolVersions.add(ProtocolVersion.TLS10);
        protocolVersions.add(ProtocolVersion.TLS11);
        protocolVersions.add(ProtocolVersion.TLS12);
    }

    @Override
    public ProbeResult call() {
        List<Config> extensionsToBeTested = new LinkedList<>();
        extensionsToBeTested.add(createExtendedMasterSecretConfig());

        List<ResultValue> resultList = new LinkedList<>();
        List<TLSCheck> checkList = new LinkedList<>();

        checkList.add(new TLSCheck(true, CheckType.CIPHERSUITE_ANON, 10));
        resultList.add(new ResultValue("Ciphersuite", "test"));

        for (Config config : extensionsToBeTested) {
            TlsContext tlsContext = new TlsContext(config);
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, tlsContext);
            try {
                workflowExecutor.executeWorkflow();
            } catch (WorkflowExecutionException ex) {
                LOGGER.warn("Encountered exception while executing WorkflowTrace!");
                LOGGER.debug(ex);
            }
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, tlsContext.getWorkflowTrace())) {
                if (tlsContext.isExtendedMasterSecretExtension()) {
                    LOGGER.warn("Found extended master secret");
                }
                else {
                    LOGGER.warn("Found nothing");
                }
            } else {
                LOGGER.warn("Server did not send ServerHello");
                LOGGER.warn(tlsContext.getWorkflowTrace().toString());
                if (tlsContext.isReceivedFatalAlert()) {
                    LOGGER.warn("Received Fatal Alert");
                    AlertMessage alert = (AlertMessage) WorkflowTraceUtil.getFirstReceivedMessage(ProtocolMessageType.ALERT, tlsContext.getWorkflowTrace());
                    LOGGER.warn("Type:" + alert.toString());

                }
            }
        }

        return new ProbeResult(getType(), resultList, checkList);
    }

    public Config createStandardConfig() {
        Config config = getConfig().createConfig();
        try{
        config.setDefaultClientSupportedCiphersuites(Arrays.asList(CipherSuite.values()));
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setEnforceSettings(true);
        config.setAddServerNameIndicationExtension(false);
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgrorithmsExtension(true);
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterFatal(true);
        List<NamedCurve> namedCurves = new LinkedList<>();
        namedCurves.addAll(Arrays.asList(NamedCurve.values()));
        config.setNamedCurves(namedCurves);}
        catch (Exception ex) {
            LOGGER.warn("Config Erstellung ging schief.");
            LOGGER.warn(ex);
        }

        return config;
    }

    public Config createExtendedMasterSecretConfig() {
        Config config = createStandardConfig();
        config.setAddExtendedMasterSecretExtension(true);
        return config;
    }

}
